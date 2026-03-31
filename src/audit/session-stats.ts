import type {
  PatternCategory,
  SessionStatsData,
  TimelineEvent,
  SafetyEvaluation,
} from "../types.js"

export class SessionStats {
  private data: SessionStatsData

  constructor(sessionId: string = "") {
    this.data = this.createEmpty(sessionId)
  }

  private createEmpty(sessionId: string): SessionStatsData {
    return {
      sessionId,
      startedAt: new Date().toISOString(),
      totalToolCalls: 0,
      totalDetections: 0,
      detectionsByCategory: {
        "api-keys": 0,
        credentials: 0,
        "private-keys": 0,
        docker: 0,
        kubernetes: 0,
        cloud: 0,
        "pii-email": 0,
        "pii-phone": 0,
        "pii-ssn": 0,
        "pii-credit-card": 0,
        "pii-ip-address": 0,
      },
      blockedAttempts: 0,
      redactedCount: 0,
      blockedFilePaths: [],
      llmDetections: 0,
      safetyBlocks: 0,
      safetyWarnings: 0,
      timeline: [],
    }
  }

  reset(sessionId: string): void {
    this.data = this.createEmpty(sessionId)
  }

  recordToolCall(): void {
    this.data.totalToolCalls++
  }

  recordDetection(
    tool: string,
    category: PatternCategory,
    count: number,
    details: string,
  ): void {
    this.data.totalDetections += count
    this.data.redactedCount += count
    this.data.detectionsByCategory[category] =
      (this.data.detectionsByCategory[category] || 0) + count

    this.addTimelineEvent({
      timestamp: new Date().toISOString(),
      type: "detection",
      tool,
      details,
      category,
    })
  }

  recordBlock(tool: string, filePath: string, reason: string): void {
    this.data.blockedAttempts++
    if (filePath && !this.data.blockedFilePaths.includes(filePath)) {
      this.data.blockedFilePaths.push(filePath)
    }

    this.addTimelineEvent({
      timestamp: new Date().toISOString(),
      type: "block",
      tool,
      details: reason,
    })
  }

  recordPass(tool: string): void {
    this.addTimelineEvent({
      timestamp: new Date().toISOString(),
      type: "pass",
      tool,
      details: "No detections",
    })
  }

  recordLlmDetections(count: number): void {
    this.data.llmDetections += count
    this.data.totalDetections += count
  }

  recordSafetyEvaluation(
    tool: string,
    evaluation: SafetyEvaluation,
  ): void {
    if (evaluation.recommendation === "block") {
      this.data.safetyBlocks++
      this.addTimelineEvent({
        timestamp: new Date().toISOString(),
        type: "safety-block",
        tool,
        details: evaluation.explanation,
      })
    } else if (evaluation.recommendation === "warn") {
      this.data.safetyWarnings++
      this.addTimelineEvent({
        timestamp: new Date().toISOString(),
        type: "safety-warn",
        tool,
        details: evaluation.explanation,
      })
    }
  }

  getSummary(): SessionStatsData {
    return { ...this.data }
  }

  getReport(format: "summary" | "detailed" = "summary"): string {
    const s = this.data
    const lines: string[] = []

    lines.push("=== Security Guard Report ===")
    lines.push(`Session: ${s.sessionId || "N/A"}`)
    lines.push(`Started: ${s.startedAt}`)
    lines.push(`Total Tool Calls: ${s.totalToolCalls}`)
    lines.push(`Total Detections: ${s.totalDetections}`)
    lines.push(`Blocked Attempts: ${s.blockedAttempts}`)
    lines.push(`Secrets Redacted: ${s.redactedCount}`)
    lines.push(`LLM Detections: ${s.llmDetections}`)
    lines.push(`Safety Blocks: ${s.safetyBlocks}`)
    lines.push(`Safety Warnings: ${s.safetyWarnings}`)

    // Category breakdown
    const activeCategories = Object.entries(s.detectionsByCategory)
      .filter(([, count]) => count > 0)
      .sort(([, a], [, b]) => b - a)

    if (activeCategories.length > 0) {
      lines.push("")
      lines.push("--- Detections by Category ---")
      for (const [cat, count] of activeCategories) {
        lines.push(`  ${cat}: ${count}`)
      }
    }

    if (s.blockedFilePaths.length > 0) {
      lines.push("")
      lines.push("--- Blocked File Paths ---")
      for (const p of s.blockedFilePaths) {
        lines.push(`  ${p}`)
      }
    }

    if (format === "detailed" && s.timeline.length > 0) {
      lines.push("")
      lines.push("--- Timeline ---")
      for (const event of s.timeline) {
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
        lines.push(
          `  [${event.timestamp}] ${icon} | ${event.tool} | ${event.details}${event.category ? ` (${event.category})` : ""}`,
        )
      }
    }

    lines.push("")
    lines.push("=== End Report ===")
    return lines.join("\n")
  }

  private addTimelineEvent(event: TimelineEvent): void {
    this.data.timeline.push(event)
    // Keep timeline manageable
    if (this.data.timeline.length > 1000) {
      this.data.timeline = this.data.timeline.slice(-500)
    }
  }
}
