import type { SecurityGuardConfig, PatternCategory } from "../types.js"

interface ConfigViewDeps {
  config: SecurityGuardConfig
}

export function createSecurityConfigTool(deps: ConfigViewDeps) {
  const { config } = deps

  return {
    description: "View active Warden configuration (read-only, secrets masked)",
    args: {},
    async execute(): Promise<string> {
      const lines: string[] = []
      lines.push("=== Warden Configuration ===")
      lines.push("")

      // Safety evaluator
      const se = config.llm.safetyEvaluator
      lines.push("--- Safety Evaluator ---")
      lines.push(`Enabled: ${se.enabled}`)
      lines.push(`Action Mode: ${se.actionMode}`)
      lines.push(`Block Threshold: ${se.blockThreshold}`)
      lines.push(`Warn Threshold: ${se.warnThreshold}`)
      lines.push(`Monitored Tools: ${se.tools.join(", ")}`)
      lines.push(`Bypassed Commands: ${se.bypassedCommands.length} patterns`)
      lines.push("")

      // Output sanitizer
      const os = config.llm.outputSanitizer
      lines.push("--- Output Sanitizer ---")
      lines.push(`Enabled: ${os.enabled}`)
      lines.push(`Action Mode: ${os.actionMode}`)
      lines.push(`Monitored Tools: ${os.tools.join(", ")}`)
      lines.push(`Max Output Size: ${os.maxOutputSize > 0 ? `${os.maxOutputSize} chars` : "unlimited"}`)
      lines.push(`Skip When Regex Clean: ${os.skipWhenRegexClean}`)
      lines.push("")

      // LLM endpoints
      lines.push("--- LLM Endpoints ---")
      lines.push(`LLM Enabled: ${config.llm.enabled}`)
      if (config.llm.enabled) {
        // Show safety evaluator providers
        if (se.providers && se.providers.length > 0) {
          lines.push("Safety Evaluator Providers:")
          for (const p of se.providers) {
            lines.push(`  - ${p.name || "unnamed"}: ${p.baseUrl || "(inherited)"} / ${p.model || "(inherited)"}`)
            lines.push(`    API Key: ${p.apiKey ? "***" : "<not set>"}`)
          }
        }
        // Show output sanitizer providers
        if (os.providers && os.providers.length > 0) {
          lines.push("Output Sanitizer Providers:")
          for (const p of os.providers) {
            lines.push(`  - ${p.name || "unnamed"}: ${p.baseUrl || "(inherited)"} / ${p.model || "(inherited)"}`)
            lines.push(`    API Key: ${p.apiKey ? "***" : "<not set>"}`)
          }
        }
      }
      lines.push("")

      // Detection categories
      const active = (Object.entries(config.categories) as [PatternCategory, boolean][])
        .filter(([, v]) => v).map(([k]) => k)
      const disabled = (Object.entries(config.categories) as [PatternCategory, boolean][])
        .filter(([, v]) => !v).map(([k]) => k)
      lines.push("--- Detection Categories ---")
      lines.push(`Active: ${active.join(", ")}`)
      if (disabled.length > 0) {
        lines.push(`Disabled: ${disabled.join(", ")}`)
      }
      lines.push("")

      // Blocked/excluded tools
      lines.push("--- Tool Control ---")
      lines.push(`Excluded Tools: ${config.excludedTools.length > 0 ? config.excludedTools.join(", ") : "none"}`)
      lines.push(`Blocked Tools: ${config.blockedTools.length > 0 ? config.blockedTools.join(", ") : "none"}`)
      lines.push("")

      // Modes
      lines.push("--- Modes ---")
      lines.push(`SSH-Only Mode: ${config.sshOnlyMode}`)
      lines.push(`Notifications: ${config.notifications}`)
      lines.push("")

      // Audit
      lines.push("--- Audit ---")
      lines.push(`Enabled: ${config.audit.enabled}`)
      lines.push(`Verbosity: ${config.audit.verbosity}`)
      lines.push(`Log Path: ${config.audit.filePath}`)
      lines.push(`Max File Size: ${Math.round(config.audit.maxFileSize / 1024 / 1024)}MB`)
      lines.push(`Max Files: ${config.audit.maxFiles}`)
      lines.push("")

      // Indirect execution
      lines.push("--- Indirect Execution Prevention ---")
      lines.push(`Enabled: ${config.indirectExecution.enabled}`)
      lines.push(`Script Extensions: ${config.indirectExecution.scriptExtensions.length} types`)
      lines.push(`Block Binaries: ${config.indirectExecution.blockBinaries}`)

      // Blocked file paths
      if (config.blockedFilePaths.length > 0) {
        lines.push("")
        lines.push("--- Blocked File Paths ---")
        for (const p of config.blockedFilePaths) {
          lines.push(`  ${p}`)
        }
      }

      return lines.join("\n")
    },
  }
}
