import { describe, test, expect } from "bun:test"
import { createSecurityConfigTool } from "../src/tools/security-config.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import type { SecurityGuardConfig } from "../src/types.js"

function makeConfig(overrides: Partial<SecurityGuardConfig> = {}): SecurityGuardConfig {
  return {
    ...JSON.parse(JSON.stringify(DEFAULT_CONFIG)),
    ...overrides,
  }
}

describe("security-config tool", () => {
  test("shows config header", async () => {
    const tool = createSecurityConfigTool({ config: DEFAULT_CONFIG })
    const result = await tool.execute()
    expect(result).toContain("=== Warden Configuration ===")
  })

  test("shows safety evaluator settings", async () => {
    const tool = createSecurityConfigTool({ config: DEFAULT_CONFIG })
    const result = await tool.execute()
    expect(result).toContain("--- Safety Evaluator ---")
    expect(result).toContain("Action Mode:")
    expect(result).toContain("Block Threshold:")
    expect(result).toContain("Warn Threshold:")
  })

  test("shows output sanitizer settings", async () => {
    const tool = createSecurityConfigTool({ config: DEFAULT_CONFIG })
    const result = await tool.execute()
    expect(result).toContain("--- Output Sanitizer ---")
    expect(result).toContain("Action Mode:")
  })

  test("shows detection categories", async () => {
    const tool = createSecurityConfigTool({ config: DEFAULT_CONFIG })
    const result = await tool.execute()
    expect(result).toContain("--- Detection Categories ---")
    expect(result).toContain("api-keys")
  })

  test("shows blocked file paths", async () => {
    const tool = createSecurityConfigTool({ config: DEFAULT_CONFIG })
    const result = await tool.execute()
    expect(result).toContain("--- Blocked File Paths ---")
    expect(result).toContain("**/.env")
  })

  test("shows SSH-only mode", async () => {
    const tool = createSecurityConfigTool({ config: DEFAULT_CONFIG })
    const result = await tool.execute()
    expect(result).toContain("SSH-Only Mode:")
  })

  test("shows audit settings", async () => {
    const tool = createSecurityConfigTool({ config: DEFAULT_CONFIG })
    const result = await tool.execute()
    expect(result).toContain("--- Audit ---")
    expect(result).toContain("Verbosity:")
  })

  test("masks API keys in provider config", async () => {
    const config = makeConfig()
    config.llm.enabled = true
    config.llm.safetyEvaluator.providers = [{
      name: "test-provider",
      cooldown: 0,
      baseUrl: "http://localhost:11434/v1",
      model: "test-model",
      apiKey: "sk-super-secret-key-12345",
      timeout: 5000,
      temperature: 0,
      headers: {},
      healthCheckPath: "/models",
      completionsPath: "/chat/completions",
    }]
    const tool = createSecurityConfigTool({ config })
    const result = await tool.execute()
    expect(result).toContain("***")
    expect(result).not.toContain("sk-super-secret-key-12345")
  })

  test("shows API key as not set when empty", async () => {
    const config = makeConfig()
    config.llm.enabled = true
    config.llm.safetyEvaluator.providers = [{
      name: "test-provider",
      cooldown: 0,
      baseUrl: "http://localhost:11434/v1",
      model: "test-model",
      apiKey: "",
      timeout: 5000,
      temperature: 0,
      headers: {},
      healthCheckPath: "/models",
      completionsPath: "/chat/completions",
    }]
    const tool = createSecurityConfigTool({ config })
    const result = await tool.execute()
    expect(result).toContain("<not set>")
  })

  test("shows indirect execution settings", async () => {
    const tool = createSecurityConfigTool({ config: DEFAULT_CONFIG })
    const result = await tool.execute()
    expect(result).toContain("--- Indirect Execution Prevention ---")
    expect(result).toContain("Block Binaries:")
  })
})
