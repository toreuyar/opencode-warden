import { describe, test, expect } from "bun:test"
import { createSecurityDashboardTool } from "../src/tools/security-dashboard.js"
import { SessionStats } from "../src/audit/session-stats.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import { ProviderChain } from "../src/llm/provider-chain.js"
import { LlmSanitizer } from "../src/llm/index.js"
import type { LlmProviderConfig, SecurityGuardConfig } from "../src/types.js"

function makeProvider(overrides: Partial<LlmProviderConfig> = {}): LlmProviderConfig {
  return {
    name: "test-provider", cooldown: 0,
    baseUrl: "http://localhost:11434/v1", model: "test",
    apiKey: "", timeout: 5000, temperature: 0,
    headers: {}, healthCheckPath: "/models", completionsPath: "/chat/completions",
    ...overrides,
  }
}

describe("security-dashboard tool", () => {
  test("dashboard output contains header and footer", async () => {
    const stats = new SessionStats("test-session")
    const tool = createSecurityDashboardTool({
      sessionStats: stats,
      config: DEFAULT_CONFIG,
      llmSanitizer: null,
    })
    const output = await tool.execute({})
    expect(output).toContain("=== Warden Dashboard ===")
    expect(output).toContain("=== End Dashboard ===")
  })

  test("shows active categories count", async () => {
    const stats = new SessionStats("test-session")
    const tool = createSecurityDashboardTool({
      sessionStats: stats,
      config: DEFAULT_CONFIG,
      llmSanitizer: null,
    })
    const output = await tool.execute({})
    expect(output).toContain("Active Categories:")
    expect(output).toContain("api-keys")
  })

  test("shows session statistics", async () => {
    const stats = new SessionStats("test-session")
    stats.recordToolCall()
    stats.recordToolCall()
    const tool = createSecurityDashboardTool({
      sessionStats: stats,
      config: DEFAULT_CONFIG,
      llmSanitizer: null,
    })
    const output = await tool.execute({})
    expect(output).toContain("Total Tool Calls: 2")
  })

  test("shows LLM sanitizer status when available", async () => {
    const stats = new SessionStats("test-session")
    const chain = new ProviderChain([makeProvider()])
    const config = { ...DEFAULT_CONFIG.llm, enabled: true } as SecurityGuardConfig["llm"]
    const sanitizer = new LlmSanitizer(config, chain)
    const tool = createSecurityDashboardTool({
      sessionStats: stats,
      config: DEFAULT_CONFIG,
      llmSanitizer: sanitizer,
    })
    const output = await tool.execute({})
    expect(output).toContain("LLM Sanitizer: Available")
    expect(output).toContain("test-provider")
    expect(output).toContain("ready")
  })

  test("shows LLM sanitizer disabled when null", async () => {
    const stats = new SessionStats("test-session")
    const tool = createSecurityDashboardTool({
      sessionStats: stats,
      config: DEFAULT_CONFIG,
      llmSanitizer: null,
    })
    const output = await tool.execute({})
    expect(output).toContain("LLM Sanitizer: Disabled")
  })

  test("shows detection breakdown when detections exist", async () => {
    const stats = new SessionStats("test-session")
    stats.recordDetection("bash", "api-keys", 2, "Found 2 API keys")
    stats.recordDetection("read", "credentials", 1, "Found password")
    const tool = createSecurityDashboardTool({
      sessionStats: stats,
      config: DEFAULT_CONFIG,
      llmSanitizer: null,
    })
    const output = await tool.execute({})
    expect(output).toContain("Detections by Category")
    expect(output).toContain("api-keys: 2")
    expect(output).toContain("credentials: 1")
  })

  test("shows blocked file paths when present", async () => {
    const stats = new SessionStats("test-session")
    stats.recordBlock("bash", "/project/.env", "Blocked file path")
    const tool = createSecurityDashboardTool({
      sessionStats: stats,
      config: DEFAULT_CONFIG,
      llmSanitizer: null,
    })
    const output = await tool.execute({})
    expect(output).toContain("Blocked File Access")
    expect(output).toContain("/project/.env")
  })

  test("shows recent events from timeline", async () => {
    const stats = new SessionStats("test-session")
    stats.recordToolCall()
    stats.recordDetection("bash", "api-keys", 1, "Found API key")
    stats.recordBlock("bash", "", "dangerous command")
    const tool = createSecurityDashboardTool({
      sessionStats: stats,
      config: DEFAULT_CONFIG,
      llmSanitizer: null,
    })
    const output = await tool.execute({})
    expect(output).toContain("Recent Events")
    expect(output).toContain("DETECT")
    expect(output).toContain("BLOCK")
  })

  test("brief mode returns single-line status", async () => {
    const stats = new SessionStats("test-session")
    const tool = createSecurityDashboardTool({
      sessionStats: stats,
      config: DEFAULT_CONFIG,
      llmSanitizer: null,
    })
    const output = await tool.execute({ mode: "brief" })
    expect(output.split("\n").length).toBe(1)
    expect(output).toContain("Warden:")
    expect(output).toContain("calls")
    expect(output).toContain("detections")
    expect(output).toContain("blocks")
    expect(output).toContain("LLM:")
  })

  test("brief mode shows OK when no issues", async () => {
    const stats = new SessionStats("test-session")
    const tool = createSecurityDashboardTool({
      sessionStats: stats,
      config: DEFAULT_CONFIG,
      llmSanitizer: null,
    })
    const output = await tool.execute({ mode: "brief" })
    expect(output).toContain("Warden: OK")
  })

  test("brief mode shows ALERT when blocks exist", async () => {
    const stats = new SessionStats("test-session")
    stats.recordBlock("bash", "/etc/passwd", "blocked")
    const tool = createSecurityDashboardTool({
      sessionStats: stats,
      config: DEFAULT_CONFIG,
      llmSanitizer: null,
    })
    const output = await tool.execute({ mode: "brief" })
    expect(output).toContain("Warden: ALERT")
  })
})
