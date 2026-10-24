import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type { SecurityGuardConfig } from "../types.js"
import { appendSecurityPolicy, type SessionContextLike } from "./outbound-sanitizer.js"
import { buildSecurityPolicyContext } from "./security-policy.js"

interface CompactionContextDeps {
  config: SecurityGuardConfig
  diagnosticLogger: DiagnosticLogger | null
  /**
   * Deterministic outbound scanner used for the native `session.compaction`
   * event (`system` / `messages` / `tools`). It appends the policy itself, so
   * the native path does not append a second copy. When omitted (legacy/test
   * callers), only the policy is appended.
   */
  sanitizeRequest?: (
    event: SessionContextLike,
    options?: { surface?: "context" | "compaction" | "title" | "generate" },
  ) => Promise<void>
}

interface LegacyCompactionOutput {
  context?: string[]
  prompt?: string
}

/**
 * Compaction runs before a summary request is sent to the provider, so it is
 * an outbound surface. The native OpenCode event exposes the same request
 * fields as `session.context` (`system`, `messages`, `tools`); we scan those
 * deterministically and append the security policy, preserving model options,
 * message metadata, provider metadata, and tool-call identity.
 *
 * Unsupported shapes throw. OpenCode has no typed failure channel for session
 * hooks, so the throw aborts request preparation rather than sending
 * unsanitized history — the intended fail-closed behavior.
 */
export function createCompactionContext(deps: CompactionContextDeps) {
  const { config, diagnosticLogger } = deps
  const policyText = buildSecurityPolicyContext(config)

  return async (
    event: unknown,
    output?: LegacyCompactionOutput,
  ) => {
    // V1-shaped callers (and the existing unit test) pass a string sink.
    // Keep that path policy-only; native callers always use the request event.
    if (output && Array.isArray(output.context)) {
      diagnosticLogger?.info("Compaction: injecting security policy context")
      if (policyText.length > 0) output.context.push(policyText)
      return
    }

    const native = event as Partial<SessionContextLike> | null | undefined
    if (
      !native ||
      typeof native !== "object" ||
      !Array.isArray(native.system) ||
      !Array.isArray(native.messages)
    ) {
      throw new Error(
        "Security Guard: compaction request shape is not supported; request blocked.",
      )
    }

    if (deps.sanitizeRequest) {
      await deps.sanitizeRequest(native as SessionContextLike, { surface: "compaction" })
    } else {
      appendSecurityPolicy(native.system, policyText)
    }

    diagnosticLogger?.info(
      "Compaction: scanned outbound request and injected security policy",
    )
  }
}
