import { describe, test, expect } from "bun:test"
import { createSecurityHelpTool } from "../src/tools/security-help.js"

describe("security-help tool", () => {
  const tool = createSecurityHelpTool()

  test("no topic returns tool list", async () => {
    const result = await tool.execute({})
    expect(result).toContain("Available Warden security tools:")
    expect(result).toContain("security_help")
    expect(result).toContain("security_dashboard")
    expect(result).toContain("security_report")
    expect(result).toContain("security_audit")
    expect(result).toContain("security_evaluate")
    expect(result).toContain("security_config")
    expect(result).toContain("security_rules")
  })

  test("topic returns detailed help", async () => {
    const result = await tool.execute({ topic: "security_audit" })
    expect(result).toContain("Query Audit Log")
    expect(result).toContain("eventType")
    expect(result).toContain("limit")
    expect(result).toContain("Example:")
  })

  test("each tool has detailed help", async () => {
    const tools = [
      "security_help", "security_dashboard", "security_report",
      "security_audit", "security_evaluate", "security_config", "security_rules",
    ]
    for (const t of tools) {
      const result = await tool.execute({ topic: t })
      expect(result).not.toContain("Unknown tool")
    }
  })

  test("unknown topic returns error with available list", async () => {
    const result = await tool.execute({ topic: "nonexistent" })
    expect(result).toContain("Unknown tool")
    expect(result).toContain("security_dashboard")
  })

  test("security_rules help mentions three-layer architecture", async () => {
    const result = await tool.execute({ topic: "security_rules" })
    expect(result).toContain("Layer 1")
    expect(result).toContain("Layer 2")
    expect(result).toContain("Layer 3")
    expect(result).toContain("session-only")
  })

  test("security_evaluate help mentions dry-run", async () => {
    const result = await tool.execute({ topic: "security_evaluate" })
    expect(result).toContain("Dry-Run")
    expect(result).toContain("WITHOUT executing")
  })

  test("security_dashboard help mentions brief mode", async () => {
    const result = await tool.execute({ topic: "security_dashboard" })
    expect(result).toContain("brief")
    expect(result).toContain("full")
  })
})
