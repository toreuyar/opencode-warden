import { readAuditEntries, type AuditQueryOptions } from "../audit/audit-reader.js"

interface AuditToolDeps {
  auditLogPath: string
  maxFiles: number
}

export function createSecurityAuditTool(deps: AuditToolDeps) {
  const { auditLogPath, maxFiles } = deps

  return {
    description: "Query audit log entries with optional filters",
    args: {
      tool: {
        type: "string" as const,
        optional: true,
        description: "Filter by tool name",
      },
      eventType: {
        type: "string" as const,
        optional: true,
        description:
          'Filter by event type: "block", "detection", "pass", "safety-block", "safety-warn"',
      },
      category: {
        type: "string" as const,
        optional: true,
        description: "Filter by detection category",
      },
      limit: {
        type: "number" as const,
        optional: true,
        description: "Max entries to return (default 20)",
      },
    },
    async execute(args: {
      tool?: string
      eventType?: string
      category?: string
      limit?: number
    }): Promise<string> {
      const options: AuditQueryOptions = {
        tool: args.tool,
        eventType: args.eventType as AuditQueryOptions["eventType"],
        category: args.category,
        limit: args.limit,
      }

      const entries = readAuditEntries(auditLogPath, maxFiles, options)

      if (entries.length === 0) {
        return "No audit entries found matching the query."
      }

      const lines: string[] = []
      lines.push(`=== Audit Log (${entries.length} entries) ===`)
      lines.push("")

      for (const entry of entries) {
        const status = entry.blocked
          ? "BLOCKED"
          : entry.safetyEvaluation?.recommendation === "warn"
            ? "WARN"
            : entry.detections.length > 0
              ? "DETECTION"
              : "PASS"

        lines.push(`[${entry.timestamp}] ${status} | ${entry.tool} (${entry.hook})`)

        if (entry.blocked && entry.blockReason) {
          lines.push(`  Reason: ${entry.blockReason.substring(0, 200)}`)
        }

        if (entry.detections.length > 0) {
          const cats = [...new Set(entry.detections.map((d) => d.category))].join(", ")
          lines.push(`  Detections: ${entry.detections.length} (${cats})`)
        }

        if (entry.safetyEvaluation) {
          const se = entry.safetyEvaluation
          lines.push(`  Safety: ${se.riskLevel} risk — ${se.explanation}`)
        }

        if (entry.redactedCount > 0) {
          lines.push(`  Redacted: ${entry.redactedCount}`)
        }
      }

      return lines.join("\n")
    },
  }
}
