import type { AuditEntry, AuditConfig, PluginClient, LogLevel } from "../types.js"
import { FileLogger } from "./file-logger.js"

export class AuditLogger {
  private fileLogger: FileLogger | null = null
  private client: PluginClient | null = null
  private verbosity: "quiet" | "normal" | "verbose"
  private enabled: boolean

  constructor(config: AuditConfig, client?: PluginClient) {
    this.enabled = config.enabled
    this.verbosity = config.verbosity
    this.client = client ?? null

    if (this.enabled) {
      this.fileLogger = new FileLogger(config, (msg) => {
        if (this.client) {
          this.client.tui.showToast({
            body: { message: `Audit: ${msg}`, variant: "warning" as const },
          }).catch(() => {})
        }
      })
    }
  }

  async log(entry: AuditEntry): Promise<void> {
    if (!this.enabled) return

    // Determine if this entry should be logged based on verbosity
    if (this.verbosity === "quiet" && !entry.blocked && entry.redactedCount === 0) {
      return
    }
    if (this.verbosity === "normal" && !entry.blocked && entry.redactedCount === 0 && !entry.safetyEvaluation && !entry.blockReason) {
      return
    }
    // "verbose" logs everything

    const jsonLine = JSON.stringify(entry)

    // Write to file
    if (this.fileLogger) {
      this.fileLogger.write(jsonLine)
    }

    // Write to OpenCode log panel
    if (this.client) {
      const level: LogLevel = entry.blocked ? "warn"
        : (entry.redactedCount > 0 || entry.safetyEvaluation || entry.blockReason) ? "info"
        : "debug"

      // Skip debug entries unless verbose
      if (level === "debug" && this.verbosity !== "verbose") return

      try {
        await this.client.app.log({
          body: {
            service: "security-guard",
            level,
            message: this.formatLogMessage(entry),
          },
        })
      } catch {
        // Don't let logging failures break tool execution
      }
    }
  }

  private formatLogMessage(entry: AuditEntry): string {
    if (entry.blocked) {
      return `BLOCKED: ${entry.tool} - ${entry.blockReason || "security policy"}`
    }
    if (entry.redactedCount > 0) {
      const categories = entry.detections.map((d) => d.category)
      const unique = [...new Set(categories)]
      return `REDACTED: ${entry.redactedCount} secret(s) in ${entry.tool} [${unique.join(", ")}]`
    }
    if (entry.safetyEvaluation) {
      return `SAFETY ${entry.safetyEvaluation.recommendation.toUpperCase()}: ${entry.tool} - risk=${entry.safetyEvaluation.riskLevel}`
    }
    if (entry.blockReason) {
      return `${entry.hook.toUpperCase()}: ${entry.tool} - ${entry.blockReason}`
    }
    return `PASS: ${entry.tool}`
  }

  flush(): void {
    this.fileLogger?.flush()
  }

  destroy(): void {
    this.fileLogger?.destroy()
  }
}

export { SessionStats } from "./session-stats.js"
export { FileLogger } from "./file-logger.js"
export { DiagnosticLogger } from "./diagnostic-logger.js"
export { LlmChatLogger } from "./llm-chat-logger.js"
