import type { SessionStats } from "../audit/session-stats.js"
import type { SecurityGuardConfig, PatternCategory } from "../types.js"
import type { LlmSanitizer } from "../llm/index.js"

interface DashboardDeps {
  sessionStats: SessionStats
  config: SecurityGuardConfig
  llmSanitizer: LlmSanitizer | null
}

export function createSecurityDashboardTool(deps: DashboardDeps) {
  const { sessionStats, config, llmSanitizer } = deps

  return {
    description:
      "View Warden status and detection statistics for the current session",
    args: {
      mode: {
        type: "string" as const,
        optional: true,
        description: 'Display mode: "full" (default) or "brief" (one-line status)',
      },
    },
    async execute(args: { mode?: string }): Promise<string> {
      const summary = sessionStats.getSummary()

      if (args.mode === "brief") {
        const hasIssues = summary.blockedAttempts > 0 || summary.safetyBlocks > 0
        const status = hasIssues ? "ALERT" : "OK"
        const llmStatus = llmSanitizer
          ? (llmSanitizer.isAvailable() ? "available" : "cooldown")
          : (config.llm.enabled ? "no providers" : "disabled")
        return `Warden: ${status} | ${summary.totalToolCalls} calls | ${summary.totalDetections} detections | ${summary.blockedAttempts} blocks | LLM: ${llmStatus}`
      }

      const activeCategories = (
        Object.entries(config.categories) as [PatternCategory, boolean][]
      )
        .filter(([, enabled]) => enabled)
        .map(([cat]) => cat)

      const lines: string[] = []
      lines.push("=== Warden Dashboard ===")
      lines.push("")

      // Status
      lines.push("--- Status ---")
      lines.push(`Active Categories: ${activeCategories.length}`)
      lines.push(`  ${activeCategories.join(", ")}`)
      if (llmSanitizer) {
        const providerInfo = llmSanitizer.getProviderChain().getProviderInfo()
        if (providerInfo.length === 0) {
          lines.push(`LLM Sanitizer: No providers configured`)
        } else {
          lines.push(`LLM Sanitizer: ${llmSanitizer.isAvailable() ? "Available" : "All providers on cooldown"}`)
          for (const p of providerInfo) {
            const status = p.onCooldown ? `cooldown (${Math.ceil(p.cooldownRemaining / 1000)}s remaining)` : "ready"
            lines.push(`  - ${p.name}: ${status}`)
          }
        }
      } else {
        lines.push(`LLM Sanitizer: ${config.llm.enabled ? "Enabled (no providers)" : "Disabled"}`)
      }
      lines.push(`LLM Safety Evaluator: ${config.llm.safetyEvaluator.enabled ? "Enabled" : "Disabled"}`)
      lines.push(`Notifications: ${config.notifications ? "On" : "Off"}`)
      lines.push("")

      // Stats
      lines.push("--- Session Statistics ---")
      lines.push(`Total Tool Calls: ${summary.totalToolCalls}`)
      lines.push(`Total Detections: ${summary.totalDetections}`)
      lines.push(`Blocked Attempts: ${summary.blockedAttempts}`)
      lines.push(`Secrets Redacted: ${summary.redactedCount}`)
      lines.push(`LLM Detections: ${summary.llmDetections}`)
      lines.push(`Safety Blocks: ${summary.safetyBlocks}`)
      lines.push(`Safety Warnings: ${summary.safetyWarnings}`)

      // Category breakdown (only non-zero)
      const activeDetections = Object.entries(summary.detectionsByCategory)
        .filter(([, count]) => count > 0)
        .sort(([, a], [, b]) => b - a)

      if (activeDetections.length > 0) {
        lines.push("")
        lines.push("--- Detections by Category ---")
        for (const [cat, count] of activeDetections) {
          lines.push(`  ${cat}: ${count}`)
        }
      }

      // Blocked paths
      if (summary.blockedFilePaths.length > 0) {
        lines.push("")
        lines.push("--- Blocked File Access ---")
        for (const p of summary.blockedFilePaths) {
          lines.push(`  ${p}`)
        }
      }

      // Recent events (last 10)
      if (summary.timeline.length > 0) {
        const recent = summary.timeline.slice(-10)
        lines.push("")
        lines.push("--- Recent Events ---")
        for (const event of recent) {
          const icon =
            event.type === "block"
              ? "BLOCK"
              : event.type === "detection"
                ? "DETECT"
                : event.type === "safety-block"
                  ? "SAFETY-BLOCK"
                  : event.type === "safety-warn"
                    ? "SAFETY-WARN"
                    : "PASS"
          lines.push(`  [${event.timestamp}] ${icon} ${event.tool}: ${event.details}`)
        }
      }

      lines.push("")
      lines.push("=== End Dashboard ===")
      return lines.join("\n")
    },
  }
}
