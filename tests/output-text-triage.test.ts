import { describe, test, expect, mock } from "bun:test"
import { OutputTextTriageEvaluator } from "../src/llm/output-text-triage.js"
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

function makeTextTriageConfig(overrides: Record<string, unknown> = {}): SecurityGuardConfig["llm"]["outputTextTriage"] {
  return {
    ...DEFAULT_CONFIG.llm.outputTextTriage,
    enabled: true,
    ...overrides,
  } as SecurityGuardConfig["llm"]["outputTextTriage"]
}

describe("OutputTextTriageEvaluator", () => {
  describe("isEnabled / isAvailable", () => {
    test("isEnabled returns config enabled state", () => {
      const config = makeTextTriageConfig({ enabled: true })
      const chain = new ProviderChain([makeProvider()])
      const triage = new OutputTextTriageEvaluator(config, chain)
      expect(triage.isEnabled()).toBe(true)
    })

    test("isAvailable delegates to provider chain", () => {
      const chain = new ProviderChain([makeProvider()])
      const triage = new OutputTextTriageEvaluator(makeTextTriageConfig(), chain)
      expect(triage.isAvailable()).toBe(true)
    })
  })

  describe("evaluate", () => {
    test("returns needsSanitization=false for clean output", async () => {
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => JSON.stringify({
        needsSanitization: false,
        reason: "no secrets in output text",
      }))
      const triage = new OutputTextTriageEvaluator(makeTextTriageConfig(), chain)
      const result = await triage.evaluate("bash", { command: "uptime" }, "12:00 up 5 days")
      expect(result.needsSanitization).toBe(false)
    })

    test("returns needsSanitization=true when secrets detected", async () => {
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => JSON.stringify({
        needsSanitization: true,
        reason: "API key found in output",
      }))
      const triage = new OutputTextTriageEvaluator(makeTextTriageConfig(), chain)
      const result = await triage.evaluate("bash", { command: "cat config" }, "API_KEY=sk-abc123")
      expect(result.needsSanitization).toBe(true)
      expect(result.reason).toContain("API key")
    })

    test("throws on LLM failure (fail-closed)", async () => {
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => { throw new Error("timeout") })
      const triage = new OutputTextTriageEvaluator(makeTextTriageConfig(), chain)
      await expect(triage.evaluate("bash", { command: "cat .env" }, "output")).rejects.toThrow("Text triage failed")
    })

    test("throws on unparseable response", async () => {
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => "not valid json")
      const triage = new OutputTextTriageEvaluator(makeTextTriageConfig(), chain)
      await expect(triage.evaluate("bash", {}, "output")).rejects.toThrow("Could not parse")
    })
  })
})
