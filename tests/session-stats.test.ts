import { describe, test, expect } from "bun:test"
import { SessionStats } from "../src/audit/session-stats.js"

describe("SessionStats", () => {
  test("initializes with empty stats", () => {
    const stats = new SessionStats("test-session")
    const summary = stats.getSummary()
    expect(summary.totalToolCalls).toBe(0)
    expect(summary.totalDetections).toBe(0)
    expect(summary.blockedAttempts).toBe(0)
    expect(summary.sessionId).toBe("test-session")
  })

  test("records tool calls", () => {
    const stats = new SessionStats()
    stats.recordToolCall()
    stats.recordToolCall()
    expect(stats.getSummary().totalToolCalls).toBe(2)
  })

  test("records detections", () => {
    const stats = new SessionStats()
    stats.recordDetection("read", "api-keys", 3, "Found 3 API keys")
    const summary = stats.getSummary()
    expect(summary.totalDetections).toBe(3)
    expect(summary.redactedCount).toBe(3)
    expect(summary.detectionsByCategory["api-keys"]).toBe(3)
  })

  test("records blocks", () => {
    const stats = new SessionStats()
    stats.recordBlock("read", "/project/.env", "Blocked file path")
    const summary = stats.getSummary()
    expect(summary.blockedAttempts).toBe(1)
    expect(summary.blockedFilePaths).toContain("/project/.env")
  })

  test("records LLM detections", () => {
    const stats = new SessionStats()
    stats.recordLlmDetections(2)
    expect(stats.getSummary().llmDetections).toBe(2)
    expect(stats.getSummary().totalDetections).toBe(2)
  })

  test("records safety evaluations", () => {
    const stats = new SessionStats()
    stats.recordSafetyEvaluation("bash", {
      safe: false,
      riskLevel: "high",
      riskDimensions: ["destruction"],
      explanation: "rm -rf detected",
      recommendation: "block",
    })
    expect(stats.getSummary().safetyBlocks).toBe(1)

    stats.recordSafetyEvaluation("bash", {
      safe: true,
      riskLevel: "medium",
      riskDimensions: ["excessive-collection"],
      explanation: "find / command",
      recommendation: "warn",
    })
    expect(stats.getSummary().safetyWarnings).toBe(1)
  })

  test("reset clears all stats", () => {
    const stats = new SessionStats("old-session")
    stats.recordToolCall()
    stats.recordDetection("read", "api-keys", 1, "test")
    stats.recordBlock("read", ".env", "blocked")

    stats.reset("new-session")
    const summary = stats.getSummary()
    expect(summary.sessionId).toBe("new-session")
    expect(summary.totalToolCalls).toBe(0)
    expect(summary.totalDetections).toBe(0)
    expect(summary.blockedAttempts).toBe(0)
  })

  test("getReport returns formatted string", () => {
    const stats = new SessionStats("test")
    stats.recordToolCall()
    stats.recordDetection("read", "api-keys", 2, "API keys found")
    stats.recordBlock("read", ".env", "blocked")

    const report = stats.getReport("summary")
    expect(report).toContain("Warden Report")
    expect(report).toContain("Total Tool Calls: 1")
    expect(report).toContain("Total Detections: 2")
    expect(report).toContain("Blocked Attempts: 1")
  })

  test("getReport detailed includes timeline", () => {
    const stats = new SessionStats("test")
    stats.recordDetection("read", "api-keys", 1, "API key found")

    const report = stats.getReport("detailed")
    expect(report).toContain("Timeline")
    expect(report).toContain("DETECT")
  })
})
