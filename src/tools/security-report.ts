import type { SessionStats } from "../audit/session-stats.js"

interface ReportDeps {
  sessionStats?: SessionStats
  getSessionStats?: () => SessionStats
}

export function createSecurityReportTool(deps: ReportDeps) {
  const getSessionStats = () => {
    const stats = deps.getSessionStats?.() ?? deps.sessionStats
    if (!stats) throw new Error("Warden: report session stats are not configured")
    return stats
  }

  return {
    description:
      "Generate a security detection report for the current session",
    args: {
      format: {
        type: "string" as const,
        optional: true,
        description:
          'Report format: "summary" (default) or "detailed" (includes full timeline)',
      },
    },
    async execute(args: { format?: string }): Promise<string> {
      const format =
        args.format === "detailed" ? "detailed" : "summary"
      const sessionStats = getSessionStats()
      return sessionStats.getReport(format as "summary" | "detailed")
    },
  }
}
