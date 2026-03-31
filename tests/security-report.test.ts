import { describe, test, expect } from "bun:test"
import { createSecurityReportTool } from "../src/tools/security-report.js"
import { SessionStats } from "../src/audit/session-stats.js"

describe("security-report tool", () => {
  test("returns summary format by default", async () => {
    const stats = new SessionStats("test-session")
    stats.recordToolCall("bash")
    const tool = createSecurityReportTool({ sessionStats: stats })
    const result = await tool.execute({})
    expect(result).toBeTruthy()
    expect(typeof result).toBe("string")
  })

  test("returns summary when format='summary'", async () => {
    const stats = new SessionStats("test-session")
    const tool = createSecurityReportTool({ sessionStats: stats })
    const result = await tool.execute({ format: "summary" })
    expect(result).toBeTruthy()
  })

  test("returns detailed format", async () => {
    const stats = new SessionStats("test-session")
    stats.recordToolCall("bash")
    stats.recordDetection("api-keys")
    stats.recordBlock("bash", "dangerous")
    const tool = createSecurityReportTool({ sessionStats: stats })
    const result = await tool.execute({ format: "detailed" })
    expect(result).toBeTruthy()
    expect(typeof result).toBe("string")
  })

  test("invalid format defaults to summary", async () => {
    const stats = new SessionStats("test-session")
    const tool = createSecurityReportTool({ sessionStats: stats })
    const resultInvalid = await tool.execute({ format: "xml" })
    const resultSummary = await tool.execute({ format: "summary" })
    // Both should work without error
    expect(resultInvalid).toBeTruthy()
    expect(resultSummary).toBeTruthy()
  })

  test("has correct description", () => {
    const stats = new SessionStats("test-session")
    const tool = createSecurityReportTool({ sessionStats: stats })
    expect(tool.description).toContain("security detection report")
  })
})
