import type { DetectionEngine } from "../detection/engine.js"
import type { AuditLogger } from "../audit/index.js"
import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type {
  DetectionMatch,
  PatternCategory,
  SecurityGuardConfig,
} from "../types.js"
import {
  extractFileTargets,
  extractRemoteFilePathsFromArgs,
  isRedactionExempt,
} from "../utils/paths.js"
import { canonicalToolName } from "../utils/tool-compat.js"

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic outbound scanning for the V2 `session.context`, `session.title`,
// and `session.generate` hooks.
//
// This layer runs immediately before provider dispatch, after conversation
// history has been projected into provider messages. It is intentionally
// deterministic: regex detection only, no LLM calls, no synthetic messages, no
// durable history writes. The event arrays are per-request projections
// (built fresh by OpenCode), so mutations here shape this request and cannot
// pollute stored history.
//
// Scope / safety:
//  - Scans model-facing text: system parts, message text/reasoning/compaction
//    text, and tool-result text/JSON values.
//  - Redacts detected string values inside historical tool-call inputs in the
//    per-request projection. Tool-call ids, names, argument keys, and the
//    object/array structure are left unchanged so provider tool pairing still
//    resolves. Inputs carrying provider-native metadata/signed/encrypted data,
//    unsupported structures, cycles, or excessive depth abort instead of being
//    rewritten.
//  - Scans media/file identifiers read-only because renaming a file reference
//    would break the provider request.
//  - Honors `redactionEnabled`, `redactOnWrite` (historical write/edit/patch
//    inputs), and path-scoped `redactionExemptPaths` when a tool result or
//    input can be attributed to the tool call that produced it.
//  - A scanner failure throws out of the context hook. OpenCode has no typed
//    failure channel for session hooks, so this aborts request preparation
//    rather than allowing unsanitized text through.
//  - This shapes one provider request only. It does not and cannot scrub the
//    durable stored tool-call input; OpenCode persists that before Warden's
//    `tool.execute.before` runs and exposes no host API to rewrite it.
// ─────────────────────────────────────────────────────────────────────────────

export interface SystemPartLike {
  type: string
  text: string
  [key: string]: unknown
}

export interface MessageContentPartLike {
  type: string
  text?: string
  id?: string
  name?: string
  input?: unknown
  result?: unknown
  [key: string]: unknown
}

export interface MessageLike {
  role?: string
  content: MessageContentPartLike[]
  [key: string]: unknown
}

/**
 * Shared provider-request projection for `session.context`, `session.title`,
 * `session.generate`, and `session.compaction`.
 *
 * `tools` is present for primary/generate/compaction requests and absent for
 * title requests: OpenCode's title call is a plain `SessionRequest` with no
 * tool definitions. The sanitizer never needs `tools`, so it stays optional.
 */
export interface SessionContextLike {
  readonly sessionID: string
  system: SystemPartLike[]
  messages: MessageLike[]
  tools?: Record<string, unknown>
}

export interface OutboundSanitizeOptions {
  /**
   * Append the per-request security policy system part. Defaults to `true` for
   * main-context/compaction/generate requests. The title request is a narrow
   * naming task with no tools; injecting a security policy there can change the
   * title output, so title callers opt out while still receiving DLP scanning.
   */
  appendPolicy?: boolean
  /**
   * Request surface used for diagnostics/audit attribution. Does not change
   * scanning behavior.
   */
  surface?: "context" | "compaction" | "title" | "generate"
}

interface OutboundScannerDeps {
  engine: DetectionEngine
  config: SecurityGuardConfig
  projectDir?: string
  policyText: string
  auditLogger: AuditLogger
  diagnosticLogger: DiagnosticLogger | null
}

interface ToolResultValueLike {
  type?: string
  value?: unknown
  [key: string]: unknown
}

interface CallReference {
  name: string
  input: Record<string, unknown>
}

const TEXT_SCANNED_PART_TYPES = new Set(["text", "reasoning", "compaction"])
const MAX_REDACTION_DEPTH = 8

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

function parseToolInput(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  if (typeof value === "string" && value.length > 0) {
    try {
      return asRecord(JSON.parse(value))
    } catch {
      return {}
    }
  }
  return {}
}

/**
 * Provider-native metadata (for example Anthropic signatures or Gemini thought
 * signatures) is cryptographically bound to the original text/result. Warden
 * cannot recompute it, so rewriting the text while keeping the metadata would
 * either corrupt the request or leave a stale signature that no longer covers
 * the redacted content. Both outcomes are unacceptable for a security layer.
 */
function hasProviderNativeMetadata(part: Record<string, unknown>): boolean {
  const metadata = part.providerMetadata
  return (
    !!metadata &&
    typeof metadata === "object" &&
    !Array.isArray(metadata) &&
    Object.keys(metadata as Record<string, unknown>).length > 0
  )
}

function hasEncryptedNativeContent(part: Record<string, unknown>): boolean {
  return typeof part.encrypted === "string" && part.encrypted.length > 0
}

function nativeMutationError(channel: string): Error {
  return new Error(
    `Security Guard: outbound ${channel} carries provider-native signed or encrypted data. ` +
      `Redacting it would corrupt the provider request, so the request is blocked instead.`,
  )
}

/**
 * Scan a text-bearing part, returning the redacted text. If the part is
 * provider-signed/encrypted and a redaction would be required, throw rather
 * than alter signed text.
 */
function scanTextPart(
  text: string,
  part: Record<string, unknown>,
  channel: string,
  findings: DetectionMatch[],
  engine: DetectionEngine,
): string {
  const scan = engine.scan(text)
  findings.push(...scan.matches)
  if (!scan.hasDetections) return text
  if (hasProviderNativeMetadata(part) || hasEncryptedNativeContent(part)) {
    throw nativeMutationError(channel)
  }
  return scan.redacted
}

function unsupportedMutationError(channel: string): Error {
  return new Error(
    `Security Guard: outbound ${channel} contains a detected secret that Warden ` +
      `cannot safely rewrite without corrupting the request structure, so the ` +
      `request is blocked instead.`,
  )
}

/**
 * Scan opaque/unsupported provider structures (media/file references) without
 * rewriting them. If a detection is present, the request is withheld because
 * silently forwarding the structure would leak and rewriting it would corrupt
 * provider pairing. Historical tool-call inputs use structural redaction
 * instead (`redactToolCallInput`); this remains for structures whose keys or
 * identifiers are semantically bound and cannot be rewritten safely.
 */
function assertUnsupportedStringsSafe(
  values: ReadonlyArray<unknown>,
  channel: string,
  engine: DetectionEngine,
): void {
  for (const value of values) {
    if (typeof value !== "string" || value.length === 0) continue
    const scan = engine.scan(value)
    if (scan.hasDetections) throw unsupportedMutationError(channel)
  }
}

function scanPartStrings(
  value: unknown,
  channel: string,
  engine: DetectionEngine,
  depth = 0,
  seen = new WeakSet<object>(),
): void {
  if (typeof value === "string") {
    assertUnsupportedStringsSafe([value], channel, engine)
    return
  }
  if (value === null || typeof value !== "object") return
  if (depth >= MAX_REDACTION_DEPTH) throw nativeMutationError(channel)
  if (seen.has(value)) return
  seen.add(value)

  if (Array.isArray(value)) {
    for (const item of value) scanPartStrings(item, channel, engine, depth + 1, seen)
    return
  }

  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    assertUnsupportedStringsSafe([key], channel, engine)
    scanPartStrings(item, channel, engine, depth + 1, seen)
  }
}

/**
 * Keys whose values are bound to provider-native metadata. Warden cannot
 * recompute those bindings, so a detected value under one of these keys is
 * rejected instead of rewritten. The tool-call part's own providerMetadata /
 * encrypted fields are checked separately before any input rewrite.
 */
const METADATA_SENSITIVE_KEYS = new Set([
  "providerMetadata",
  "encrypted",
  "signature",
  "thoughtSignature",
])

function isPlainObject(value: object): boolean {
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

/**
 * Structural redaction of a historical tool-call input projection.
 *
 * Call ids, tool names, argument keys, and the object/array shape are preserved;
 * only detected string leaves are replaced. Unsupported or metadata-sensitive
 * structures throw instead of falling back to the raw value. The caller applies
 * the returned projection only when at least one string actually changed.
 */
function redactToolCallInput(
  value: unknown,
  part: Record<string, unknown>,
  channel: string,
  findings: DetectionMatch[],
  engine: DetectionEngine,
  depth = 0,
  seen = new WeakSet<object>(),
): unknown {
  if (typeof value === "string") {
    const scan = engine.scan(value)
    findings.push(...scan.matches)
    if (!scan.hasDetections) return value
    if (hasProviderNativeMetadata(part) || hasEncryptedNativeContent(part)) {
      throw nativeMutationError(channel)
    }
    return scan.redacted
  }

  if (value === null || value === undefined) return value
  if (typeof value === "number" || typeof value === "boolean") return value
  if (typeof value !== "object") {
    throw unsupportedMutationError(channel)
  }
  if (depth >= MAX_REDACTION_DEPTH) throw unsupportedMutationError(channel)
  if (seen.has(value)) throw unsupportedMutationError(channel)
  seen.add(value)

  if (Array.isArray(value)) {
    return value.map((item) =>
      redactToolCallInput(item, part, channel, findings, engine, depth + 1, seen),
    )
  }

  if (!isPlainObject(value)) throw unsupportedMutationError(channel)

  const result: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const keyScan = engine.scan(key)
    // Argument keys are part of the provider tool-call schema. Renaming one
    // would change the tool's meaning, so a detection in a key is not safely
    // rewritable.
    if (keyScan.hasDetections) throw unsupportedMutationError(channel)

    if (METADATA_SENSITIVE_KEYS.has(key)) {
      const probe: DetectionMatch[] = []
      redactToolCallInput(item, part, channel, probe, engine, depth + 1, seen)
      if (probe.length > 0) throw nativeMutationError(channel)
      Object.defineProperty(result, key, {
        value: item,
        enumerable: true,
        configurable: true,
        writable: true,
      })
      continue
    }

    Object.defineProperty(result, key, {
      value: redactToolCallInput(
        item,
        part,
        channel,
        findings,
        engine,
        depth + 1,
        seen,
      ),
      enumerable: true,
      configurable: true,
      writable: true,
    })
  }
  return result
}

/**
 * Redact a tool-call input only when a detected string value actually changes.
 * String-encoded JSON inputs keep their string representation; object inputs
 * keep their object shape. The original input object is never mutated.
 */
function redactToolCallInputProjection(
  input: unknown,
  part: Record<string, unknown>,
  channel: string,
  findings: DetectionMatch[],
  engine: DetectionEngine,
): unknown {
  if (input === null || input === undefined) return input
  const before = findings.length

  if (typeof input === "string") {
    if (input.length === 0) return input
    let parsed: unknown
    try {
      parsed = JSON.parse(input)
    } catch {
      // A non-JSON string input cannot be structurally rewritten. Scan it
      // read-only and withhold on detection rather than forwarding raw bytes.
      assertUnsupportedStringsSafe([input], channel, engine)
      return input
    }
    const redacted = redactToolCallInput(parsed, part, channel, findings, engine)
    return findings.length > before ? JSON.stringify(redacted) : input
  }

  if (typeof input !== "object") throw unsupportedMutationError(channel)
  const redacted = redactToolCallInput(input, part, channel, findings, engine)
  return findings.length > before ? redacted : input
}

/**
 * Append the security policy as a stable per-request system part.
 *
 * There is deliberately no marker-based deduplication: a conversation can
 * contain arbitrary text, so any text marker (including our own heading) can be
 * forged by user/assistant content. OpenCode builds `event.system` anew for
 * every request; appending exactly once per invocation is both stable and
 * unspoofable. The policy is never written to stored history.
 */
export function appendSecurityPolicy(
  system: SystemPartLike[],
  policyText: string,
): void {
  if (policyText.length === 0) return
  system.push({ type: "text", text: policyText })
}

function resultIsExempt(
  part: MessageContentPartLike,
  calls: Map<string, CallReference>,
  config: SecurityGuardConfig,
  projectDir?: string,
): boolean {
  if (typeof part.id !== "string") return false
  const call = calls.get(part.id)
  if (!call) return false

  const tool = canonicalToolName(call.name)
  if (tool !== "read" && tool !== "glob" && tool !== "grep" && tool !== "shell") {
    return false
  }

  const readTargets: Array<{ path: string; host?: string }> = extractFileTargets(
    tool,
    call.input,
  )
    .filter((target) => target.mode === "read")
    .map((target) => ({ path: target.path }))

  if (tool === "shell") {
    for (const remote of extractRemoteFilePathsFromArgs(tool, call.input)) {
      if (remote.mode === "read") {
        readTargets.push({ path: remote.path, host: remote.host })
      }
    }
  }

  // Path attribution is all-or-nothing: merged tool output cannot be split per
  // source file. A result with no attributable read target is never exempt.
  if (readTargets.length === 0) return false
  return readTargets.every((target) =>
    isRedactionExempt(target.path, config.redactionExemptPaths, {
      cwd: projectDir,
      host: target.host,
    }),
  )
}

export function createOutboundSanitizer(deps: OutboundScannerDeps) {
  const { engine, config, projectDir, policyText, auditLogger, diagnosticLogger } = deps

  /**
   * Deterministic redaction of JSON-like tool-result values. Structure is
   * reconstructed, never mutated in place, so values that alias stored history
   * are not written back. Depth/cycle guards bound hostile output.
   */
  const redactJsonValue = (
    value: unknown,
    findings: DetectionMatch[],
    depth = 0,
    seen = new WeakSet<object>(),
  ): unknown => {
    if (typeof value === "string") {
      const result = engine.scan(value)
      findings.push(...result.matches)
      return result.hasDetections ? result.redacted : value
    }
    if (value === null || typeof value !== "object") return value
    if (depth >= MAX_REDACTION_DEPTH) return "[TRUNCATED]"
    if (seen.has(value)) return "[Circular]"
    seen.add(value)

    if (Array.isArray(value)) {
      return value.map((item) => redactJsonValue(item, findings, depth + 1, seen))
    }

    const result: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") continue
      const keyScan = engine.scan(key)
      findings.push(...keyScan.matches)
      let safeKey = keyScan.hasDetections ? keyScan.redacted : key
      let uniqueKey = safeKey
      let suffix = 1
      while (Object.prototype.hasOwnProperty.call(result, uniqueKey)) {
        uniqueKey = `${safeKey}#${suffix++}`
      }
      result[uniqueKey] = redactJsonValue(item, findings, depth + 1, seen)
    }
    return result
  }

  const redactResultValue = (
    result: ToolResultValueLike,
    part: Record<string, unknown>,
    findings: DetectionMatch[],
  ): unknown => {
    if (result.type === "content" && Array.isArray(result.value)) {
      // Text content is redacted in place structurally. File parts are
      // provider-native references: their identifiers are checked for secrets
      // but never rewritten. If one contains a detection, the whole request is
      // withheld (see assertUnsupportedStringsSafe) because renaming a file
      // reference would break the tool result.
      let changed = false
      const value = result.value.map((item) => {
        const record = asRecord(item)
        if (record.type === "text" && typeof record.text === "string") {
          const text = scanTextPart(
            record.text,
            part,
            "tool result",
            findings,
            engine,
          )
          if (text !== record.text) {
            changed = true
            return { ...record, text }
          }
          return item
        }
        if (record.type === "file") {
          assertUnsupportedStringsSafe(
            [record.uri, record.name, record.mime],
            "tool result file reference",
            engine,
          )
          return item
        }
        scanPartStrings(record, "tool result structure", engine)
        return item
      })
      return changed ? value : result.value
    }

    const before = findings.length
    const value = redactJsonValue(result.value, findings)
    if (findings.length > before && hasProviderNativeMetadata(part)) {
      throw nativeMutationError("tool result")
    }
    return value
  }

  const scanMediaPart = (
    part: Record<string, unknown>,
    channel: string,
  ): void => {
    const media = asRecord(part.media)
    const source = asRecord(media.source)
    assertUnsupportedStringsSafe(
      [
        part.filename,
        part.name,
        part.uri,
        media.mediaType,
        source.url,
        source.id,
        source.mediaType,
      ],
      channel,
      engine,
    )
  }

  /**
   * A historical tool-call input is exempt from outbound scanning when the
   * input sanitizer deliberately left it unredacted:
   *  - write/edit/patch inputs when `redactOnWrite` is false (the input
   *    sanitizer skips those tools entirely), or
   *  - every write target matches `redactionExemptPaths` (all-or-nothing,
   *    matching the input sanitizer's path rule).
   *
   * Without the `redactOnWrite` mirror, a historical write/edit/patch input
   * that was intentionally stored unredacted would abort the next context or
   * compaction request. Shell is handled by path exemption only because
   * `redactOnWrite` never disables shell redaction.
   */
  const toolCallInputExempt = (
    name: string,
    input: Record<string, unknown>,
  ): boolean => {
    const tool = canonicalToolName(name)
    if (tool === "write" || tool === "edit" || tool === "patch") {
      if (!config.redactOnWrite) return true
    } else if (tool !== "shell") {
      return false
    }
    const writeTargets = extractFileTargets(tool, input).filter(
      (target) => target.mode === "write",
    )
    if (writeTargets.length === 0) return false
    return writeTargets.every((target) =>
      isRedactionExempt(target.path, config.redactionExemptPaths, {
        cwd: projectDir,
      }),
    )
  }

  return async (
    event: SessionContextLike,
    options: OutboundSanitizeOptions = {},
  ): Promise<void> => {
    if (!Array.isArray(event.system) || !Array.isArray(event.messages)) {
      throw new Error(
        "Security Guard: outbound request shape is not supported; request blocked.",
      )
    }

    const surface = options.surface ?? "context"
    const surfaceLabel = `session.${surface}`

    if (options.appendPolicy !== false) {
      appendSecurityPolicy(event.system, policyText)
    }

    // `redactionEnabled` is the master kill switch for in-place redaction. Tool
    // policy, output redaction, and env stripping remain unaffected.
    if (!config.redactionEnabled) {
      diagnosticLogger?.decision(
        "outbound-sanitizer",
        surfaceLabel,
        "Outbound redaction disabled (redactionEnabled=false)",
      )
      return
    }

    const findings: DetectionMatch[] = []

    // Tool-result exemption needs the originating call. Historical tool-call
    // inputs are indexed and their string leaves are redacted in this request's
    // projection; ids/names/keys/structure are untouched so call/result pairing
    // and provider replay remain valid. The stored session input is not
    // rewritten here (the host offers no pre-persist rewrite surface).
    const calls = new Map<string, CallReference>()
    for (const message of event.messages) {
      if (!message || !Array.isArray(message.content)) continue
      for (const part of message.content) {
        if (!part || part.type !== "tool-call") continue
        // Index the original input first so result-path exemption still sees the
        // real path even if a secret elsewhere in the same input is redacted.
        const input = parseToolInput(part.input)
        if (typeof part.id === "string" && typeof part.name === "string") {
          calls.set(part.id, {
            name: part.name,
            input,
          })
        }

        const exempt =
          typeof part.name === "string" && toolCallInputExempt(part.name, input)
        if (exempt) continue
        const redacted = redactToolCallInputProjection(
          part.input,
          part as Record<string, unknown>,
          "tool-call input",
          findings,
          engine,
        )
        if (redacted !== part.input) part.input = redacted
      }
    }

    for (const systemPart of event.system) {
      if (!systemPart || typeof systemPart.text !== "string") continue
      if (!TEXT_SCANNED_PART_TYPES.has(systemPart.type)) continue
      systemPart.text = scanTextPart(
        systemPart.text,
        systemPart as Record<string, unknown>,
        "system text",
        findings,
        engine,
      )
    }

    for (const message of event.messages) {
      if (!message || !Array.isArray(message.content)) continue

      for (const part of message.content) {
        if (!part || typeof part.type !== "string") continue

        if (part.type === "tool-result") {
          if (typeof part.result !== "object" || part.result === null) continue
          const result = part.result as ToolResultValueLike
          if (resultIsExempt(part, calls, config, projectDir)) continue
          const value = redactResultValue(
            result,
            part as Record<string, unknown>,
            findings,
          )
          if (value !== result.value) {
            part.result = { ...result, value }
          }
          continue
        }

        // Tool-call inputs were structurally redacted above.
        if (part.type === "tool-call") continue

        if (part.type === "media") {
          scanMediaPart(part as Record<string, unknown>, "media part")
          continue
        }

        if (part.type === "file") {
          assertUnsupportedStringsSafe(
            [part.uri, part.name, part.mime],
            "file part",
            engine,
          )
          continue
        }

        if (TEXT_SCANNED_PART_TYPES.has(part.type)) {
          if (typeof part.text !== "string") continue
          part.text = scanTextPart(
            part.text,
            part as Record<string, unknown>,
            `${part.type} text`,
            findings,
            engine,
          )
          continue
        }

        // Unknown/unsupported part: if it carries model-visible text we cannot
        // safely rewrite, withhold on a detection instead of silently leaking.
        if (typeof part.text === "string") {
          assertUnsupportedStringsSafe(
            [part.text],
            `part type "${part.type}"`,
            engine,
          )
        }
        if (typeof part.value === "string") {
          assertUnsupportedStringsSafe(
            [part.value],
            `part type "${part.type}"`,
            engine,
          )
        }
      }
    }

    if (findings.length === 0) return

    const categories = new Map<PatternCategory, number>()
    for (const match of findings) {
      categories.set(match.category, (categories.get(match.category) ?? 0) + 1)
    }
    diagnosticLogger?.step(
      "outbound-sanitizer",
      `Outbound ${surface}: redacted ${findings.length} secret(s)`,
    )

    try {
      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: surfaceLabel,
        hook: surface,
        sessionId: event.sessionID,
        callId: "",
        detections: findings.map((match) => ({
          patternId: match.patternId,
          category: match.category,
          confidence: match.confidence,
        })),
        blocked: false,
        blockReason: undefined,
        redactedCount: findings.length,
      })
    } catch {
      // Audit failure is non-critical; the already-redacted request continues.
    }
  }
}
