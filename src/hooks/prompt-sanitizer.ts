import type { DetectionEngine } from "../detection/engine.js"
import type { AuditLogger } from "../audit/index.js"
import type { SessionStats } from "../audit/session-stats.js"
import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type {
  SecurityGuardConfig,
  PluginClient,
  ToastState,
  PatternCategory,
  ScanResult,
} from "../types.js"

/**
 * Shape of a chat.message Part as defined by @opencode-ai/sdk.
 * We use a structural subset — only the fields we inspect — so the hook
 * stays resilient to SDK additions.
 */
type AnyPart = { type: string; [key: string]: unknown }

interface PromptSanitizerDeps {
  engine: DetectionEngine
  config: SecurityGuardConfig
  auditLogger: AuditLogger
  sessionStats?: SessionStats
  client: PluginClient
  toastState?: ToastState
  diagnosticLogger: DiagnosticLogger | null
  getSessionState?: (sessionID: string) => {
    sessionStats: SessionStats
    toastState: ToastState
  }
}

function canToast(state: ToastState): boolean {
  const now = Date.now()
  if (now - state.lastToastTime < state.minInterval) return false
  state.lastToastTime = now
  return true
}

/**
 * Extract text that the LLM will see from a chat.message Part.
 * Returns an empty array for parts that don't carry user-controllable text.
 *
 * - TextPart:           text (skips synthetic system-generated parts)
 * - subtask:            prompt (delegated subagent prompt)
 * - everything else:    ignored (file, tool, reasoning, snapshot, etc.)
 */
function extractPartText(part: AnyPart): Array<{ text: string; source: string }> {
  if (part.type === "text") {
    if (part.synthetic === true) return []
    const text = typeof part.text === "string" ? part.text : ""
    return [{ text, source: "text" }]
  }
  if (part.type === "subtask") {
    const prompt = typeof part.prompt === "string" ? part.prompt : ""
    return [{ text: prompt, source: "subtask" }]
  }
  return []
}

/**
 * Attachment metadata available on OpenCode's `session.prompt` hook before the
 * host materializes file contents. Only names, descriptions, URIs, IDs, and
 * mention text are inspected — Warden never reads the attached file itself.
 */
export interface PromptAttachmentMeta {
  files?: ReadonlyArray<unknown>
  agents?: ReadonlyArray<unknown>
  skills?: ReadonlyArray<unknown>
}

const asRecord = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null

function stringField(record: Record<string, unknown>, key: string): string | undefined {
  return typeof record[key] === "string" ? (record[key] as string) : undefined
}

function mentionText(record: Record<string, unknown>): string | undefined {
  const mention = asRecord(record.mention)
  return mention ? stringField(mention, "text") : undefined
}

function extractAttachmentTexts(
  attachments: PromptAttachmentMeta | undefined,
): Array<{ text: string; source: string }> {
  if (!attachments) return []

  const extracted: Array<{ text: string; source: string }> = []
  const push = (value: string | undefined, source: string): void => {
    if (value && value.length > 0) extracted.push({ text: value, source })
  }

  const walk = (
    list: ReadonlyArray<unknown> | undefined,
    kind: "file" | "agent" | "skill",
  ): void => {
    if (!Array.isArray(list)) return
    list.forEach((item, index) => {
      const record = asRecord(item)
      if (!record) return
      const label = `${kind} attachment[${index}]`

      if (kind === "file") {
        // A data: URI is inline file content, not metadata. Leave it to the
        // normal content path (which this hook deliberately never reads).
        const uri = stringField(record, "uri")
        if (uri && !uri.startsWith("data:")) {
          push(uri, `${label} uri`)
        }
        push(stringField(record, "name"), `${label} name`)
        push(stringField(record, "description"), `${label} description`)
      } else if (kind === "agent") {
        push(stringField(record, "name"), `${label} name`)
      } else {
        push(stringField(record, "id"), `${label} id`)
        push(stringField(record, "name"), `${label} name`)
      }

      push(mentionText(record), `${label} mention`)
    })
  }

  walk(attachments.files, "file")
  walk(attachments.agents, "agent")
  walk(attachments.skills, "skill")
  return extracted
}

export function createPromptSanitizer(deps: PromptSanitizerDeps) {
  const { engine, config, auditLogger, client, diagnosticLogger } = deps

  const getState = (sessionID: string) => {
    if (deps.getSessionState) return deps.getSessionState(sessionID)
    if (!deps.sessionStats || !deps.toastState) {
      throw new Error("Warden: prompt sanitizer session state is not configured")
    }
    return { sessionStats: deps.sessionStats, toastState: deps.toastState }
  }

  return async (
    input: {
      sessionID: string
      agent?: string
      model?: { providerID: string; modelID: string }
      messageID?: string
      variant?: string
    },
    output: {
      message: unknown
      parts: AnyPart[]
      attachments?: PromptAttachmentMeta
    },
  ) => {
    const hookStart = Date.now()

    // Opt-in gate — the prompt sanitizer is OFF by default. Users must set
    // scanUserPrompts: true to enable it. This is conservative because the
    // OpenCode TUI surfaces a generic "Session error" toast on blocked
    // prompts (the detailed reason is only in the audit log).
    if (!config.scanUserPrompts) {
      diagnosticLogger?.hookEnd(
        "chat.message",
        "prompt",
        input.messageID ?? "",
        Date.now() - hookStart,
        { outcome: "skipped", reason: "scanUserPrompts=false" },
      )
      return
    }

    // Master kill switch — when redaction is disabled, the engine isn't
    // allowed to influence any flow. Skip without throwing.
    if (!config.redactionEnabled) {
      diagnosticLogger?.hookEnd(
        "chat.message",
        "prompt",
        input.messageID ?? "",
        Date.now() - hookStart,
        { outcome: "skipped", reason: "redactionEnabled=false" },
      )
      return
    }

    const { sessionStats, toastState } = getState(input.sessionID)
    diagnosticLogger?.hookStart(
      "chat.message",
      "prompt",
      input.messageID ?? "",
      input.sessionID,
      { partCount: output.parts.length },
    )

    const debugLog = config.llm.debug
      ? (msg: string) => {
          client.app
            .log({ body: { service: "warden", level: "info", message: msg } })
            .catch(() => {})
        }
      : undefined

    const blockOnDetections = async (
      result: ScanResult,
      source: string,
      location: string,
    ): Promise<never> => {
      // Secret detected — record per-category stats
      const categoryMap = new Map<PatternCategory, number>()
      for (const m of result.matches) {
        categoryMap.set(m.category, (categoryMap.get(m.category) || 0) + 1)
      }
      for (const [cat, count] of categoryMap) {
        sessionStats.recordDetection(
          "prompt",
          cat,
          count,
          `Blocked prompt containing ${count} secret(s)`,
        )
      }
      sessionStats.recordBlock(
        "prompt",
        source === "subtask" ? "<subtask prompt>" : "<user prompt>",
        "Blocked prompt: secret detected in chat.message",
      )

      const patternSummary = result.matches
        .slice(0, 3)
        .map((m) => `${m.patternName} (${m.category})`)
        .join(", ")
      const more = result.matches.length > 3 ? `, +${result.matches.length - 3} more` : ""

      diagnosticLogger?.decision(
        "chat.message",
        "prompt",
        `BLOCKED prompt: ${result.matches.length} detection(s) in ${location} (${source}): ${patternSummary}${more}`,
      )

      // Audit log (best-effort, must not throw)
      try {
        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: "prompt",
          hook: "chat.message",
          sessionId: input.sessionID,
          callId: input.messageID ?? "",
          detections: result.matches.map((m) => ({
            patternId: m.patternId,
            category: m.category,
            confidence: m.confidence,
          })),
          blocked: true,
          blockReason: `Blocked prompt: secret detected in ${location} (${source}) (${patternSummary}${more})`,
          redactedCount: 0,
        })
      } catch {
        /* audit failure is non-critical */
      }

      // Toast (best-effort, must not throw). Note: the OpenCode TUI shows
      // a generic "Session error" toast for chat.message throws; this toast
      // here is a best-effort additional signal and may be dedup'd by the
      // rate limiter.
      if (config.notifications && canToast(toastState)) {
        try {
          await client.tui.showToast({
            body: {
              message: `🛡 Blocked prompt: contains ${result.matches.length} secret(s) — see audit log for details`,
              variant: "error" as const,
            },
          })
        } catch {
          /* toast failure is non-critical */
        }
      }

      debugLog?.(
        `Prompt sanitizer: BLOCKED messageID=${input.messageID ?? "?"} ${location} source=${source} detections=${result.matches.length}`,
      )

      // Throw to abort message creation. The OpenCode runtime catches this
      // via Effect.promise failure → propagates up to the prompt handler,
      // which (in the async path) publishes Session.Event.Error and (in the
      // sync HTTP path) returns 400. The message is NOT persisted to session
      // storage — sessions.updateMessage runs only after this hook returns.
      throw new Error(
        `Warden: User prompt blocked by security policy.\n` +
          `Reason: message contains ${result.matches.length} detected secret(s): ${patternSummary}${more}.\n` +
          `Remove or redact the secret and resend. See audit log for details.`,
      )
    }

    // Walk all parts, extract text, scan in one pass per part.
    // On the first part containing a secret, log + throw to block creation.
    for (let i = 0; i < output.parts.length; i++) {
      const part = output.parts[i]
      const texts = extractPartText(part)
      if (texts.length === 0) continue

      for (const { text, source } of texts) {
        if (!text) continue
        const result = engine.scan(text)
        if (!result.hasDetections) continue
        await blockOnDetections(result, source, `part[${i}]`)
      }
    }

    // Attachment metadata is user-supplied and reaches the provider request.
    // Scan names/URIs/descriptions/mentions only; file contents are never read.
    const attachmentTexts = extractAttachmentTexts(output.attachments)
    for (const { text, source } of attachmentTexts) {
      const result = engine.scan(text)
      if (!result.hasDetections) continue
      await blockOnDetections(result, source, "attachment metadata")
    }

    diagnosticLogger?.hookEnd(
      "chat.message",
      "prompt",
      input.messageID ?? "",
      Date.now() - hookStart,
      { outcome: "pass" },
    )
  }
}
