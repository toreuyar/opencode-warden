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
 * The returned handler:
 *   1. Updates the session's lastAgent/lastModel/lastVariant fields
 *   2. NEVER throws — capture is non-critical and must not block downstream
 *      handlers (like prompt-sanitizer) from running
 *
 * In index.ts this is composed with prompt-sanitizer: capture runs first,
 * then the sanitizer runs and may throw to block the message. Capture must
 * happen first so we record the user's intent even for blocked prompts
 * (useful for forensic audit of what the user tried to send).
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
  ): Promise<void> => {
    if (!input.sessionID) return
    try {
      const sessionState = getSessionState(input.sessionID)
      if (input.agent !== undefined) sessionState.lastAgent = input.agent
      if (input.model !== undefined) sessionState.lastModel = input.model
      if (input.variant !== undefined) sessionState.lastVariant = input.variant
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
