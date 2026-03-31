import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type { SecurityGuardConfig } from "../types.js"
import { buildSecurityPolicyContext } from "./security-policy.js"

interface CompactionContextDeps {
  config: SecurityGuardConfig
  diagnosticLogger: DiagnosticLogger | null
}

export function createCompactionContext(deps: CompactionContextDeps) {
  const { config, diagnosticLogger } = deps

  return async (
    _input: unknown,
    output: { context: string[]; prompt?: string },
  ) => {
    diagnosticLogger?.info("Compaction: injecting security policy context")
    output.context.push(buildSecurityPolicyContext(config))
  }
}
