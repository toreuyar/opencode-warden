import { describe, test, expect } from "bun:test"
import { createSecurityEvaluateTool } from "../src/tools/security-evaluate.js"

describe("security-evaluate tool", () => {
  test("returns not enabled when safetyEvaluator is null", async () => {
    const tool = createSecurityEvaluateTool({ safetyEvaluator: null })
    const result = await tool.execute({ tool: "bash", command: "ls" })
    expect(result).toContain("not enabled")
  })

  test("requires command or args", async () => {
    const tool = createSecurityEvaluateTool({ safetyEvaluator: null })
    // safetyEvaluator is null so it returns "not enabled" before arg check
    // Test with a mock evaluator to hit the arg validation
  })

  test("rejects invalid JSON args", async () => {
    const mockEvaluator = {
      dryRun: async () => ({
        safe: true,
        riskLevel: "none" as const,
        riskDimensions: [],
        explanation: "safe",
        suggestedAlternative: "",
        recommendation: "allow" as const,
      }),
      isBypassed: () => false,
    }
    const tool = createSecurityEvaluateTool({ safetyEvaluator: mockEvaluator as never })
    const result = await tool.execute({ tool: "write", args: "{bad json" })
    expect(result).toContain("valid JSON")
  })

  test("formats evaluation result correctly", async () => {
    const mockEvaluator = {
      dryRun: async () => ({
        safe: false,
        riskLevel: "high" as const,
        riskDimensions: ["destruction" as const],
        explanation: "deletes system files",
        suggestedAlternative: "delete specific files instead",
        recommendation: "block" as const,
      }),
    }
    const tool = createSecurityEvaluateTool({ safetyEvaluator: mockEvaluator as never })
    const result = await tool.execute({ tool: "bash", command: "rm -rf /" })
    expect(result).toContain("Safety Evaluation (dry-run)")
    expect(result).toContain("Risk Level: high")
    expect(result).toContain("Recommendation: block")
    expect(result).toContain("destruction")
    expect(result).toContain("deletes system files")
    expect(result).toContain("delete specific files instead")
  })

  test("shows bypassed result", async () => {
    const mockEvaluator = {
      dryRun: async () => ({
        safe: true,
        riskLevel: "none" as const,
        riskDimensions: [],
        explanation: "Pre-approved (bypassed command)",
        suggestedAlternative: "",
        recommendation: "allow" as const,
      }),
    }
    const tool = createSecurityEvaluateTool({ safetyEvaluator: mockEvaluator as never })
    const result = await tool.execute({ tool: "bash", command: "ls -la" })
    expect(result).toContain("Safe: Yes")
    expect(result).toContain("Risk Level: none")
    expect(result).toContain("allow")
  })
})
