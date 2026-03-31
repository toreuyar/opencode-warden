import { describe, test, expect, mock } from "bun:test"
import { LlmSanitizer } from "../src/llm/index.js"
import { ProviderChain } from "../src/llm/provider-chain.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import type { SecurityGuardConfig, LlmProviderConfig } from "../src/types.js"

function makeProvider(overrides: Partial<LlmProviderConfig> = {}): LlmProviderConfig {
  return {
    name: "test", cooldown: 0,
    baseUrl: "http://localhost:11434/v1", model: "test",
    apiKey: "", timeout: 5000, temperature: 0,
    headers: {}, healthCheckPath: "/models", completionsPath: "/chat/completions",
    ...overrides,
  }
}

function makeLlmConfig(overrides: Record<string, unknown> = {}): SecurityGuardConfig["llm"] {
  return {
    ...DEFAULT_CONFIG.llm,
    enabled: true,
    ...overrides,
    outputSanitizer: {
      ...DEFAULT_CONFIG.llm.outputSanitizer,
      ...((overrides.outputSanitizer || {}) as Record<string, unknown>),
    },
  } as SecurityGuardConfig["llm"]
}

describe("LlmSanitizer", () => {
  describe("shouldSanitize", () => {
    test("returns true for tools in the configured list when enabled", () => {
      const config = makeLlmConfig()
      const chain = new ProviderChain([makeProvider()])
      const sanitizer = new LlmSanitizer(config, chain)
      // Default tools: read, bash, grep
      expect(sanitizer.shouldSanitize("read")).toBe(true)
      expect(sanitizer.shouldSanitize("bash")).toBe(true)
      expect(sanitizer.shouldSanitize("grep")).toBe(true)
    })

    test("returns false for tools not in the list", () => {
      const config = makeLlmConfig()
      const chain = new ProviderChain([makeProvider()])
      const sanitizer = new LlmSanitizer(config, chain)
      expect(sanitizer.shouldSanitize("write")).toBe(false)
      expect(sanitizer.shouldSanitize("edit")).toBe(false)
    })

    test("returns false when LLM is disabled", () => {
      const config = makeLlmConfig({ enabled: false })
      const chain = new ProviderChain([makeProvider()])
      const sanitizer = new LlmSanitizer(config, chain)
      expect(sanitizer.shouldSanitize("bash")).toBe(false)
    })

    test("returns false when outputSanitizer is disabled", () => {
      const config = makeLlmConfig({ outputSanitizer: { enabled: false } })
      const chain = new ProviderChain([makeProvider()])
      const sanitizer = new LlmSanitizer(config, chain)
      expect(sanitizer.shouldSanitize("bash")).toBe(false)
    })
  })

  describe("sanitize", () => {
    test("returns findings when LLM detects secrets", async () => {
      const config = makeLlmConfig()
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => JSON.stringify({
        needsSanitization: true,
        findings: [
          { sensitive: "sk-abc123", category: "api-key", occurrences: 1 },
        ],
      }))
      const sanitizer = new LlmSanitizer(config, chain)
      const result = await sanitizer.sanitize("bash", "Output: sk-abc123")
      expect(result.needsSanitization).toBe(true)
      expect(result.findings).toHaveLength(1)
      expect(result.findings[0].sensitive).toBe("sk-abc123")
    })

    test("returns clean result when no secrets found", async () => {
      const config = makeLlmConfig()
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => JSON.stringify({
        needsSanitization: false,
        findings: [],
      }))
      const sanitizer = new LlmSanitizer(config, chain)
      const result = await sanitizer.sanitize("bash", "safe output")
      expect(result.needsSanitization).toBe(false)
      expect(result.findings).toHaveLength(0)
    })

    test("throws on LLM unreachable (fail-closed)", async () => {
      const config = makeLlmConfig()
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => { throw new Error("connection refused") })
      const sanitizer = new LlmSanitizer(config, chain)
      await expect(sanitizer.sanitize("bash", "output")).rejects.toThrow("LLM sanitization failed")
    })

    test("throws on timeout", async () => {
      const config = makeLlmConfig()
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => { throw new Error("request timed out") })
      const sanitizer = new LlmSanitizer(config, chain)
      await expect(sanitizer.sanitize("bash", "output")).rejects.toThrow("timed out")
    })

    test("throws on unparseable LLM response", async () => {
      const config = makeLlmConfig()
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => "not json")
      const sanitizer = new LlmSanitizer(config, chain)
      await expect(sanitizer.sanitize("bash", "output")).rejects.toThrow("parsing failed")
    })

    test("throws on inconsistency: needsSanitization=true but no findings", async () => {
      const config = makeLlmConfig()
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => JSON.stringify({
        needsSanitization: true,
        findings: [],
      }))
      const sanitizer = new LlmSanitizer(config, chain)
      await expect(sanitizer.sanitize("bash", "output")).rejects.toThrow("inconsistency")
    })

    test("filters out findings with empty sensitive field", async () => {
      const config = makeLlmConfig()
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => JSON.stringify({
        needsSanitization: true,
        findings: [
          { sensitive: "real-secret", category: "api-key", occurrences: 1 },
          { sensitive: "", category: "unknown", occurrences: 0 },
        ],
      }))
      const sanitizer = new LlmSanitizer(config, chain)
      const result = await sanitizer.sanitize("bash", "output with real-secret")
      expect(result.findings).toHaveLength(1)
      expect(result.findings[0].sensitive).toBe("real-secret")
    })
  })

  describe("isAvailable / healthCheck", () => {
    test("isAvailable delegates to provider chain", () => {
      const chain = new ProviderChain([makeProvider()])
      const sanitizer = new LlmSanitizer(makeLlmConfig(), chain)
      expect(sanitizer.isAvailable()).toBe(true)
    })

    test("isAvailable returns false with no providers", () => {
      const chain = new ProviderChain([])
      const sanitizer = new LlmSanitizer(makeLlmConfig(), chain)
      expect(sanitizer.isAvailable()).toBe(false)
    })

    test("getProviderChain returns the chain", () => {
      const chain = new ProviderChain([makeProvider()])
      const sanitizer = new LlmSanitizer(makeLlmConfig(), chain)
      expect(sanitizer.getProviderChain()).toBe(chain)
    })
  })
})
