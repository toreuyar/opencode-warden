import { describe, test, expect } from "bun:test"
import { createDetectionEngine } from "../src/detection/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"

describe("createDetectionEngine", () => {
  test("creates an engine with default config", () => {
    const engine = createDetectionEngine(DEFAULT_CONFIG)
    expect(engine).toBeTruthy()
    // Should have patterns loaded
    const patterns = engine.getPatterns()
    expect(patterns.length).toBeGreaterThan(0)
  })

  test("collects warnings for invalid custom patterns", () => {
    const warnings: string[] = []
    const config = {
      ...DEFAULT_CONFIG,
      customPatterns: [
        {
          id: "bad-regex",
          name: "Bad Regex",
          category: "api-keys" as const,
          pattern: "[invalid(", // broken regex
          redactTemplate: "****",
          confidence: "high" as const,
        },
      ],
    }
    const engine = createDetectionEngine(config, warnings)
    expect(engine).toBeTruthy()
    expect(warnings.length).toBeGreaterThan(0)
    expect(warnings[0]).toContain("bad-regex")
  })

  test("respects disabled categories", () => {
    const config = {
      ...DEFAULT_CONFIG,
      categories: {
        ...DEFAULT_CONFIG.categories,
        "api-keys": false,
      },
    }
    const engine = createDetectionEngine(config)
    const patterns = engine.getPatterns()
    // None of the patterns should be from api-keys category
    const apiKeyPatterns = patterns.filter((p) => p.category === "api-keys")
    expect(apiKeyPatterns.length).toBe(0)
  })

  test("respects disabledPatterns list", () => {
    const config = {
      ...DEFAULT_CONFIG,
      disabledPatterns: ["openai-api-key"],
    }
    const engine = createDetectionEngine(config)
    const patterns = engine.getPatterns()
    const openaiPattern = patterns.find((p) => p.id === "openai-api-key")
    expect(openaiPattern).toBeUndefined()
  })

  test("includes valid custom patterns", () => {
    const config = {
      ...DEFAULT_CONFIG,
      customPatterns: [
        {
          id: "custom-token",
          name: "Custom Token",
          category: "api-keys" as const,
          pattern: "myapp_[A-Za-z0-9]{32}",
          redactTemplate: "myapp_****",
          confidence: "high" as const,
        },
      ],
    }
    const engine = createDetectionEngine(config)
    // Engine should detect the custom pattern
    const result = engine.scan("myapp_" + "a".repeat(32))
    expect(result.hasDetections).toBe(true)
    expect(result.matches[0].patternId).toBe("custom-token")
  })
})
