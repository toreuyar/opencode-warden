import type { DetectionEngine } from "../detection/engine.js"
import type {
  FailClosedFailure,
  PermissionDecision,
  PermissionInput,
} from "../types.js"

export type { FailClosedFailure } from "../types.js"

// ─────────────────────────────────────────────────────────────────────────────
// OpenCode V2 adapters
//
// These live outside src/index.ts so the event-shape mapping can be exercised
// without booting the plugin. The security modules keep their V1-shaped
// (input, output) contracts; everything V2-specific is translated here.
// ─────────────────────────────────────────────────────────────────────────────

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

const BLOCKED_PREFIX = "[BLOCKED]"

// ─── Permission evaluation ───────────────────────────────────────────────────

/**
 * Shape of `ctx.permission.hook("evaluate")` in @opencode/plugin 2.x
 * (`PermissionEvaluation`). V2 only.
 */
export interface PermissionEvaluationEvent {
  readonly sessionID: string
  readonly action: string
  readonly resources: ReadonlyArray<string>
  readonly metadata?: Readonly<Record<string, unknown>>
  /**
   * Tool-originated permission requests carry
   * `{ type: "tool", messageID, id }`. OpenCode constructs it from the tool
   * context: `id` is the Tool.CallID, i.e. the exact same id emitted by
   * `tool.execute.before` / `tool.execute.after`.
   */
  readonly source?: {
    readonly type?: string
    readonly messageID?: string
    readonly id?: string
  }
  effect: "allow" | "ask" | "deny"
  message?: string
}

export type PermissionHandlerFn = (
  input: PermissionInput,
  output: PermissionDecision,
) => Promise<void>

/**
 * Bridge a V2 PermissionEvaluation onto the shared permission handler.
 *
 * `source.id` is the tool call id (verified against OpenCode's shell/edit/
 * write/patch/subagent permission calls), so it is forwarded both as the
 * handler's `callID` and as the deduplication key shared with the input
 * sanitizer. `event.message` is exposed through accessors because the handler
 * writes denial text back onto its decision object.
 */
export function createPermissionAdapter(handler: PermissionHandlerFn) {
  return async (event: PermissionEvaluationEvent): Promise<void> => {
    const metadata = asRecord(event.metadata)
    const statusView: PermissionDecision = {
      get status() {
        return event.effect
      },
      set status(value: "allow" | "ask" | "deny") {
        event.effect = value
      },
      get message() {
        return event.message
      },
      set message(value: string | undefined) {
        event.message = value
      },
    }

    await handler(
      {
        id: event.source?.id ?? "",
        action: event.action,
        resources: [...event.resources],
        sessionID: event.sessionID,
        messageID: event.source?.messageID ?? "",
        callID: event.source?.id,
        // V2 has no separate title. The shell tool puts its command in
        // metadata.command; other tools leave this empty.
        title: typeof metadata.command === "string" ? metadata.command : "",
        metadata,
        message: event.message,
        tool: event.source
          ? { messageID: event.source.messageID, callID: event.source.id }
          : undefined,
        time: { created: Date.now() },
      },
      statusView,
    )
  }
}

// ─── tool.execute.after ──────────────────────────────────────────────────────

export interface ToolContentPart {
  readonly type: string
  readonly text?: string
}

export interface ToolResultLike {
  output?: unknown
  content?: string | ReadonlyArray<ToolContentPart>
  metadata?: Readonly<Record<string, unknown>>
}

export interface ToolErrorLike {
  message?: string
  error?: unknown
  metadata?: Readonly<Record<string, unknown>>
}

interface ToolAfterBase {
  readonly tool: string
  readonly sessionID: string
  readonly id: string
  readonly input: unknown
}

export type ToolAfterEvent =
  | (ToolAfterBase & { readonly status: "completed"; result: ToolResultLike })
  | (ToolAfterBase & { readonly status: "error"; error: ToolErrorLike })

export type OutputRedactorFn = (
  input: {
    tool: string
    sessionID: string
    callID: string
    args?: Record<string, unknown>
  },
  output: {
    output: string
    title: string
    metadata: Record<string, unknown>
  },
) => Promise<void>

interface ToolAfterDeps {
  redactor: OutputRedactorFn
  engine: DetectionEngine
}

interface RedactionHolder {
  output: string
  title: string
  metadata: Record<string, unknown>
}

function safeStringify(value: unknown): string {
  if (typeof value === "string") return value
  try {
    const json = JSON.stringify(value)
    return json === undefined ? String(value) : json
  } catch {
    return "[Unserializable content withheld]"
  }
}

function isTextContentPart(
  part: ToolContentPart | undefined,
): part is ToolContentPart & { text: string } {
  return (
    !!part &&
    typeof part === "object" &&
    part.type === "text" &&
    typeof part.text === "string"
  )
}

function joinedTextFromContent(
  content: string | ReadonlyArray<ToolContentPart> | undefined,
): string | undefined {
  if (typeof content === "string") return content
  if (!Array.isArray(content)) return undefined
  const texts = content.filter(isTextContentPart).map((part) => part.text)
  return texts.length > 0 ? texts.join("\n") : undefined
}

function redactString(value: string, engine: DetectionEngine): string {
  const result = engine.scan(value)
  return result.hasDetections ? result.redacted : value
}

/**
 * Deterministic (regex) redaction of metadata values. Metadata is not the
 * model's primary content channel, but it is persisted in the session/UI and
 * can therefore leak secrets. Structural values are reconstructed rather than
 * mutated in place. Depth and cycle guards keep hostile tool output bounded.
 */
export function redactMetadataValues(
  value: unknown,
  engine: DetectionEngine,
  depth = 0,
  seen: WeakSet<object> = new WeakSet(),
): unknown {
  if (typeof value === "string") return redactString(value, engine)
  if (value === null || typeof value !== "object") return value

  if (depth >= 8) return "[TRUNCATED]"
  if (seen.has(value)) return "[Circular]"
  seen.add(value)

  if (Array.isArray(value)) {
    return value.map((item) => redactMetadataValues(item, engine, depth + 1, seen))
  }
  if (value instanceof Error) {
    return {
      name: value.name,
      message: redactString(value.message, engine),
    }
  }

  const result: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    // Never allow metadata to reassign the prototype chain when it is copied.
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue
    // Keys are persisted too, so a secret used as a key must not survive.
    const safeKey = redactString(key, engine)
    let uniqueKey = safeKey
    let suffix = 1
    while (Object.prototype.hasOwnProperty.call(result, uniqueKey)) {
      uniqueKey = `${safeKey}#${suffix++}`
    }
    result[uniqueKey] = redactMetadataValues(item, engine, depth + 1, seen)
  }
  return result
}

function redactedMetadata(
  metadata: Readonly<Record<string, unknown>>,
  engine: DetectionEngine,
): Record<string, unknown> {
  return redactMetadataValues(metadata, engine) as Record<string, unknown>
}

function blockedHolder(holder: RedactionHolder, reason: string): void {
  holder.output = `[BLOCKED] ${reason}`
  holder.title = "[BLOCKED] Output withheld"
}

/**
 * Run the existing output sanitizer (regex + optional LLM). Any unexpected
 * failure is converted to a withheld output; this adapter never lets a
 * sanitizer exception fall through to the model.
 */
async function runRedactor(
  redactor: OutputRedactorFn,
  input: Parameters<OutputRedactorFn>[0],
  holder: RedactionHolder,
): Promise<boolean> {
  try {
    await redactor(input, holder)
    return true
  } catch {
    blockedHolder(holder, "Sanitizer failed — output withheld for safety")
    return false
  }
}

/**
 * The model-visible error is resolved the same way OpenCode's `toSessionError`
 * resolves a Tool.Error: an inner `error` cause wins over the outer message
 * when it has one. We scan that value, then drop the cause so an unsanitized
 * nested message can never become model-visible later.
 */
function modelVisibleErrorMessage(error: unknown, depth = 0): string {
  if (error === null || error === undefined) return ""
  if (typeof error !== "object") return String(error)
  if (depth >= 8) return ""

  const record = error as { message?: unknown; error?: unknown }
  if (record.error !== undefined && record.error !== null) {
    const inner = modelVisibleErrorMessage(record.error, depth + 1)
    if (inner !== "") return inner
  }
  return typeof record.message === "string" ? record.message : ""
}

/**
 * Error metadata also goes through the output sanitizer so LLM-only secret
 * shapes are covered, not just regex-known ones. If the sanitizer withholds or
 * cannot preserve a JSON object, metadata is dropped entirely.
 */
async function sanitizeErrorMetadata(
  metadata: Readonly<Record<string, unknown>>,
  engine: DetectionEngine,
  redactor: OutputRedactorFn,
  input: Parameters<OutputRedactorFn>[0],
): Promise<Record<string, unknown> | undefined> {
  if (Object.keys(metadata).length === 0) return undefined

  const serialized = safeStringify(metadata)
  const holder: RedactionHolder = { output: serialized, title: "", metadata: {} }
  const completed = await runRedactor(redactor, input, holder)
  if (!completed || holder.output.startsWith(BLOCKED_PREFIX)) return undefined

  if (holder.output !== serialized) {
    try {
      const parsed = JSON.parse(holder.output)
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined
      return redactedMetadata(parsed as Record<string, unknown>, engine)
    } catch {
      // A sanitizer rewrite that is no longer valid JSON is not trustworthy.
      return undefined
    }
  }

  return redactedMetadata(metadata, engine)
}

/**
 * Apply output sanitization to a V2 `tool.execute.after` event.
 *
 * Handles both success and error events:
 *  - completed: scans textual content, or JSON-serializes structured `output`
 *    when the tool returned no model-facing content (content-less fallback).
 *  - error: scans the model-visible error message (including an unwrapped
 *    cause) and metadata, and removes the cause after sanitizing.
 *
 * Redaction switches and exemptions are enforced inside the existing output
 * redactor. When an enabled LLM sanitizer is unavailable, the redactor emits a
 * `[BLOCKED]` marker; this adapter then removes structured output/metadata so
 * the raw value cannot leak through another channel.
 */
export function createExecuteAfterAdapter(deps: ToolAfterDeps) {
  const { redactor, engine } = deps

  return async (event: ToolAfterEvent): Promise<void> => {
    const input = {
      tool: event.tool,
      sessionID: event.sessionID,
      callID: event.id,
      args: asRecord(event.input),
    }

    if (event.status === "error") {
      const originalMetadata = asRecord(event.error.metadata)
      const originalTitle =
        typeof originalMetadata.title === "string" ? originalMetadata.title : ""
      const message = modelVisibleErrorMessage(event.error)
      const holder: RedactionHolder = {
        output: message,
        title: originalTitle,
        metadata: originalMetadata,
      }

      const completed = await runRedactor(redactor, input, holder)
      const blocked = !completed || holder.output.startsWith(BLOCKED_PREFIX)

      event.error.message = holder.output
      // OpenCode prefers an inner cause's message when present. Drop it after
      // scanning so only the sanitized outer message can reach the model.
      event.error.error = undefined

      if (blocked) {
        event.error.metadata = undefined
        return
      }

      const metadata = await sanitizeErrorMetadata(
        originalMetadata,
        engine,
        redactor,
        input,
      )
      if (metadata === undefined) {
        event.error.metadata = undefined
      } else {
        event.error.metadata =
          holder.title.length > 0 ? { ...metadata, title: holder.title } : metadata
      }
      return
    }

    const originalContent = event.result.content
    const hasMetadata = event.result.metadata !== undefined
    const originalMetadata = asRecord(event.result.metadata)
    const originalTitle =
      typeof originalMetadata.title === "string" ? originalMetadata.title : ""

    const sanitizedMetadata = redactedMetadata(originalMetadata, engine)
    const metadataTitle =
      typeof sanitizedMetadata.title === "string" ? sanitizedMetadata.title : originalTitle

    const contentIsArray = Array.isArray(originalContent)
    const contentText = joinedTextFromContent(originalContent)
    const structuredFallback =
      contentText === undefined && event.result.output !== undefined

    let nextContent: string | ReadonlyArray<ToolContentPart> | undefined = originalContent
    let nextOutput: unknown = event.result.output
    let contentChanged = false
    let blocked = false
    let finalTitle = metadataTitle

    const runSinglePass = async (sourceText: string): Promise<RedactionHolder> => {
      const holder: RedactionHolder = {
        output: sourceText,
        title: metadataTitle,
        metadata: sanitizedMetadata,
      }
      const completed = await runRedactor(redactor, input, holder)
      if (!completed || holder.output.startsWith(BLOCKED_PREFIX)) blocked = true
      if (holder.title.length > 0) finalTitle = holder.title
      if (holder.output !== sourceText) contentChanged = true
      return holder
    }

    if (contentIsArray && contentText !== undefined) {
      const parts = originalContent as ReadonlyArray<ToolContentPart>
      const hasNonTextParts = parts.some((part) => !isTextContentPart(part))

      if (hasNonTextParts) {
        // File/image parts are provider-native references and must survive text
        // redaction unchanged. Run the redactor per text part and rebuild the
        // array; never collapse the result to one string (which would drop
        // file parts).
        let firstText = true
        let blockedOutput: string | undefined
        const sanitized: ToolContentPart[] = []
        for (const part of parts) {
          if (!isTextContentPart(part)) {
            sanitized.push(part)
            continue
          }
          const holder: RedactionHolder = {
            output: part.text,
            // Title/metadata are handled once, not once per text part.
            title: firstText ? metadataTitle : "",
            metadata: sanitizedMetadata,
          }
          const completed = await runRedactor(redactor, input, holder)
          firstText = false
          if (!completed || holder.output.startsWith(BLOCKED_PREFIX)) {
            blocked = true
            blockedOutput ??= holder.output
          }
          if (holder.title.length > 0) finalTitle = holder.title
          if (holder.output !== part.text) contentChanged = true
          sanitized.push(
            holder.output === part.text ? part : { ...part, text: holder.output },
          )
        }
        // A blocked text part withholds the whole result: do not leave file
        // parts or other text reachable when one channel could not be sanitized.
        nextContent = blocked
          ? (blockedOutput ?? "[BLOCKED] Output withheld for safety")
          : sanitized
      } else {
        const holder = await runSinglePass(contentText)
        if (contentChanged || blocked) nextContent = holder.output
      }
    } else if (typeof originalContent === "string") {
      const holder = await runSinglePass(originalContent)
      if (contentChanged || blocked) nextContent = holder.output
    } else if (structuredFallback) {
      const holder = await runSinglePass(safeStringify(event.result.output))
      if (contentChanged || blocked) {
        // Drop the redundant structured copy. When the visible content is an
        // array of file parts and only the hidden structured value changed,
        // keep those file parts; a blocked result withholds everything.
        nextContent =
          contentIsArray && !blocked ? originalContent : holder.output
        nextOutput = undefined
      }
    }

    let nextMetadata: Record<string, unknown> | undefined
    if (blocked) {
      nextMetadata = { title: finalTitle || "[BLOCKED] Output withheld" }
    } else if (hasMetadata || finalTitle.length > 0) {
      nextMetadata = { ...sanitizedMetadata }
      if (finalTitle.length > 0) nextMetadata.title = finalTitle
    }

    if (contentChanged || blocked) {
      event.result = {
        ...event.result,
        content: nextContent,
        // Never leave a copy of the raw structured result on the event when the
        // model-facing text was redacted or withheld.
        output: undefined,
        ...(nextMetadata === undefined ? {} : { metadata: nextMetadata }),
      }
    } else if (nextMetadata !== undefined || nextOutput !== event.result.output) {
      event.result = {
        ...event.result,
        output: nextOutput,
        ...(nextMetadata === undefined ? {} : { metadata: nextMetadata }),
      }
    }
  }
}

// ─── Configuration failure lockdown ──────────────────────────────────────────

const FAIL_CLOSED_LABEL = "Warden configuration failure"

export const FAIL_CLOSED_MESSAGES = {
  permission:
    "Warden: Permission denied — Warden configuration is invalid. " +
    "Fix the configuration and restart OpenCode.",
  tool:
    "Security Guard: Warden configuration is invalid. Tool execution is blocked " +
    "until the configuration is fixed and OpenCode is restarted.",
  session:
    "Security Guard: Warden configuration is invalid. Session prompts and model " +
    "requests are blocked until the configuration is fixed and OpenCode is restarted.",
  shell:
    "Security Guard: Warden configuration is invalid. Shell creation is blocked " +
    "until the configuration is fixed and OpenCode is restarted.",
  output:
    "[BLOCKED] Warden configuration is invalid — output withheld. " +
    "Fix the configuration and restart OpenCode.",
  error:
    "Security Guard: Warden configuration is invalid — tool error details withheld. " +
    "Fix the configuration and restart OpenCode.",
} as const

type LooseHook = (
  name: any,
  callback: (event: any) => any,
) => any

export interface FailClosedContext {
  readonly permission: { readonly hook: LooseHook }
  readonly tool: { readonly hook: LooseHook }
  readonly session: { readonly hook: LooseHook }
  readonly shell: { readonly hook: LooseHook }
}

export function failClosedPermissionCallback() {
  return (event: { effect: "allow" | "ask" | "deny"; message?: string }): void => {
    event.effect = "deny"
    event.message = FAIL_CLOSED_MESSAGES.permission
  }
}

export function failClosedBlockingCallback(message: string) {
  return (): never => {
    throw new Error(message)
  }
}

/**
 * Withhold every result shape even if a tool was already in flight when the
 * configuration became invalid. This path deliberately does not construct a
 * detection engine or LLM: it replaces content, output, error cause, and
 * metadata with fixed text so unknown content cannot escape.
 */
export function failClosedAfterCallback() {
  return (event: ToolAfterEvent): void => {
    if (event.status === "error") {
      event.error.message = FAIL_CLOSED_MESSAGES.error
      event.error.error = undefined
      event.error.metadata = undefined
      return
    }
    event.result = {
      content: FAIL_CLOSED_MESSAGES.output,
      output: undefined,
      metadata: undefined,
    }
  }
}

/**
 * Register a deny-all / block-all hook set for an invalid configuration.
 *
 * OpenCode drops plugins whose setup throws, so this must be installed and
 * setup must return normally. `execute.before` is a typed veto; prompt,
 * session-context, compaction/generate/title, and shell hooks have no typed
 * failure channel, so their throw aborts preparation/spawn as a defect. This is
 * still fail-closed (the operation does not proceed), but it is not a clean
 * user-facing veto — see the handoff notes.
 */
export async function registerFailClosedHooks(
  ctx: FailClosedContext,
  failure: FailClosedFailure,
): Promise<void> {
  const source = failure.source || "unknown"
  const label = `${FAIL_CLOSED_LABEL} (${source})`
  const location = failure.path ? ` at ${failure.path}` : ""
  const issueDetail = (failure.issues ?? [])
    .map((issue) => {
      const prefix = issue.path ? `${issue.path}: ` : ""
      return `${prefix}${issue.message ?? issue.code ?? "invalid value"}`
    })
    .filter((item) => item.length > 0)
    .join("; ")
  const detail = issueDetail
    ? `: ${issueDetail}`
    : failure.message
      ? `: ${failure.message}`
      : ""

  // Sanitized diagnostics only — never log the loader's input or resolved config.
  console.error(
    `[warden] ${label}${location}${detail}. Registering fail-closed lockdown hooks.`,
  )

  const sessionBlock = failClosedBlockingCallback(FAIL_CLOSED_MESSAGES.session)

  // Attempt every registration even if one domain fails. A partial lockdown is
  // still better than aborting setup (which would drop all hooks).
  const registrations = [
    // Deny every permission request, including existing sessions.
    ctx.permission.hook("evaluate", failClosedPermissionCallback()),
    // Typed veto for every tool call.
    ctx.tool.hook(
      "execute.before",
      failClosedBlockingCallback(FAIL_CLOSED_MESSAGES.tool),
    ),
    // Existing in-flight calls can still reach after; withhold everything.
    ctx.tool.hook("execute.after", failClosedAfterCallback()),
    // Block user prompts and every outbound session request path that can
    // carry existing conversation content to a provider.
    ...([
      "prompt",
      "context",
      "compaction",
      "generate",
      "title",
      "model.request",
      "http.request",
      "experimental.ws.handshake",
      "experimental.ws.send",
    ] as const).map((name) => ctx.session.hook(name, sessionBlock)),
    // User shells created outside the tool path must not spawn either.
    ctx.shell.hook(
      "create.before",
      failClosedBlockingCallback(FAIL_CLOSED_MESSAGES.shell),
    ),
  ]

  const results = await Promise.allSettled(registrations)
  const failed = results.filter((result) => result.status === "rejected").length
  if (failed > 0) {
    // Sanitized: no registration error details can contain config values.
    console.error(
      `[warden] ${label}: ${failed} fail-closed hook(s) failed to register.`,
    )
  }
}
