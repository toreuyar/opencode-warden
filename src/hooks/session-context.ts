/**
 * Extract the session ID from an OpenCode lifecycle event.
 *
 * Per @opencode-ai/sdk@1.3.9 the typed shape for `session.created` and
 * `session.deleted` is:
 *
 *   { type: "session.created" | "session.deleted", properties: { info: Session } }
 *
 * where `Session.id` is the session ID. Other events (e.g. `session.idle`,
 * `session.status`, `message.removed`) use `properties.sessionID` directly.
 *
 * We try the typed shapes first, then fall back to legacy top-level fields
 * for forward/backward tolerance. Returns "" if no session ID can be found.
 */
export function extractEventSessionID(event: unknown): string {
  if (!event || typeof event !== "object") return ""
  const record = event as Record<string, unknown>

  const properties = record.properties
  if (properties && typeof properties === "object") {
    const propsRec = properties as Record<string, unknown>

    // session.created / session.deleted / message.updated: properties.info.id
    const info = propsRec.info
    if (info && typeof info === "object") {
      const infoRec = info as Record<string, unknown>
      if (typeof infoRec.id === "string" && infoRec.id.length > 0) return infoRec.id
    }

    // session.idle / session.status / message.removed: properties.sessionID
    if (typeof propsRec.sessionID === "string" && propsRec.sessionID.length > 0) {
      return propsRec.sessionID
    }
  }

  // Legacy / untyped fallbacks (do not rely on these for new events)
  if (typeof record.sessionID === "string" && record.sessionID.length > 0) return record.sessionID
  if (typeof record.sessionId === "string" && record.sessionId.length > 0) return record.sessionId
  return ""
}

/**
 * Minimal structural view of a session's security state, for the
 * session-context capture hook. Mirrors fields from SessionSecurityState
 * in index.ts without importing it (avoids circular dependency).
 */
export interface SessionContextTarget {
  lastAgent?: string
  lastModel?: { providerID: string; modelID: string }
  lastVariant?: string
  lastAccessed: number
}

/**
 * Factory for the chat.message handler that captures per-session context
 * (agent/model/variant) for later use by policy injection. Extracted from
 * index.ts so the capture logic is unit-testable in isolation.
 *
 * Capture reads RESOLVED values from output.message (always present per
 * @opencode-ai/sdk's UserMessage type) rather than optional request fields
 * on input. This prevents the stale-mixture bug where a new message that
 * only specifies agent would inherit model/variant from an earlier message
 * that used a different agent — the resolved message reflects what OpenCode
 * actually selected, not what the user requested.
 *
 * `variant` is not on the resolved UserMessage in @opencode-ai/sdk@1.3.9.
 * We capture it from input when present and CLEAR stale state when absent,
 * so an old variant from a different agent context cannot contaminate a
 * later message.
 *
 * The returned handler:
 *   1. Updates the session's lastAgent/lastModel/lastVariant fields
 *   2. NEVER throws — capture is non-critical and must not block downstream
 *      handlers (like prompt-sanitizer) from running
 *
 * In index.ts this is composed with prompt-sanitizer: capture runs first,
 * then the sanitizer runs and may throw to block the message.
 */
export function createSessionContextCapture<T extends SessionContextTarget>(
  getSessionState: (sessionID: string) => T,
) {
  return async (
    input: {
      sessionID: string
      agent?: string
      model?: { providerID: string; modelID: string }
      variant?: string
    },
    output?: { message?: unknown },
  ): Promise<void> => {
    if (!input.sessionID) return
    try {
      const sessionState = getSessionState(input.sessionID)

      // Capture RESOLVED agent/model from the output message. These are
      // always present on UserMessage per the SDK contract — prefer them
      // over input.* which reflects the request, not what OpenCode selected.
      // We treat output.message as unknown and validate at runtime so the
      // wrapper in index.ts doesn't need to cast SDK types.
      const msg = output?.message
      if (msg && typeof msg === "object") {
        const m = msg as Record<string, unknown>
        if (typeof m.agent === "string") {
          sessionState.lastAgent = m.agent
        }
        const model = m.model
        if (model && typeof model === "object"
            && typeof (model as Record<string, unknown>).providerID === "string"
            && typeof (model as Record<string, unknown>).modelID === "string") {
          sessionState.lastModel = model as { providerID: string; modelID: string }
        }
      }

      // variant is NOT on the resolved UserMessage. Capture from input when
      // explicitly provided; otherwise CLEAR stale state so a previous
      // message's variant cannot leak into a later message that doesn't
      // specify one (which OpenCode would resolve from the agent config).
      if (input.variant !== undefined) {
        sessionState.lastVariant = input.variant
      } else {
        sessionState.lastVariant = undefined
      }
    } catch {
      // Non-critical — context capture must never block the sanitizer
    }
  }
}

/**
 * Pure TTL sweep function. Removes entries from the sessions map whose
 * lastAccessed is older than the cutoff. Returns the list of swept IDs
 * (for diagnostics / testing).
 *
 * Extracted from index.ts so we can test the sweep logic without timers.
 * The caller (index.ts) wraps this in setInterval.
 */
export function sweepStaleSessions<T extends SessionContextTarget>(
  sessions: Map<string, T>,
  now: number,
  ttlMs: number,
): string[] {
  const cutoff = now - ttlMs
  const swept: string[] = []
  for (const [id, state] of sessions) {
    if (state.lastAccessed < cutoff) {
      sessions.delete(id)
      swept.push(id)
    }
  }
  return swept
}
