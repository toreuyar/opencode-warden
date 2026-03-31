import type { DetectionEngine } from "../detection/engine.js"
import type { AuditLogger } from "../audit/index.js"
import type { SessionStats } from "../audit/session-stats.js"
import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type { SecurityGuardConfig, PluginClient, ToastState } from "../types.js"

interface EnvSanitizerDeps {
  engine: DetectionEngine
  config: SecurityGuardConfig
  auditLogger: AuditLogger
  sessionStats: SessionStats
  client: PluginClient
  toastState: ToastState
  diagnosticLogger: DiagnosticLogger | null
}

function canToast(state: ToastState): boolean {
  const now = Date.now()
  if (now - state.lastToastTime < state.minInterval) return false
  state.lastToastTime = now
  return true
}

/**
 * Match an env var name against a glob pattern (supports * wildcard).
 */
function matchEnvPattern(name: string, pattern: string): boolean {
  // Convert glob pattern to regex
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
  return new RegExp(`^${regexStr}$`).test(name)
}

export function createEnvSanitizer(deps: EnvSanitizerDeps) {
  const { engine, config, auditLogger, client, toastState, diagnosticLogger } = deps

  return async (
    _input: { cwd: string },
    output: { env: Record<string, string> },
  ) => {
    const hookStart = Date.now()
    diagnosticLogger?.hookStart("env-sanitizer", "shell", "", "")

    if (config.sshOnlyMode) {
      diagnosticLogger?.hookEnd("env-sanitizer", "shell", "", Date.now() - hookStart, { outcome: "skipped", reason: "sshOnlyMode" })
      return
    }

    if (!config.env.enabled) {
      diagnosticLogger?.hookEnd("env-sanitizer", "shell", "", Date.now() - hookStart, { outcome: "skipped", reason: "disabled" })
      return
    }

    let redactedValues = 0
    let strippedNames = 0
    const affectedVars: string[] = []

    // Step 1: Scan all env var VALUES through detection engine
    for (const [key, value] of Object.entries(output.env)) {
      if (typeof value !== "string" || value.length === 0) continue

      const result = engine.scan(value)
      if (result.hasDetections) {
        output.env[key] = result.redacted
        redactedValues += result.matches.length
        affectedVars.push(key)
      }
    }

    // Step 2: Strip env vars matching name patterns
    for (const [key] of Object.entries(output.env)) {
      const shouldStrip = config.env.stripPatterns.some((pattern) =>
        matchEnvPattern(key, pattern),
      )
      if (shouldStrip) {
        output.env[key] = "[REDACTED]"
        strippedNames++
        if (!affectedVars.includes(key)) {
          affectedVars.push(key)
        }
      }
    }

    const totalAffected = redactedValues + strippedNames

    if (totalAffected > 0) {
      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: "shell",
        hook: "env",
        sessionId: "",
        callId: "",
        detections: [],
        blocked: false,
        blockReason: undefined,
        redactedCount: totalAffected,
      })

      if (config.notifications && canToast(toastState)) {
        try {
          await client.tui.showToast({
            body: {
              message: `🔒 Sanitized ${totalAffected} env var(s): ${affectedVars.slice(0, 3).join(", ")}${affectedVars.length > 3 ? "..." : ""}`,
              variant: "warning" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }
    }

    diagnosticLogger?.hookEnd("env-sanitizer", "shell", "", Date.now() - hookStart, {
      outcome: totalAffected > 0 ? "sanitized" : "clean",
      redactedValues,
      strippedNames,
    })
  }
}
