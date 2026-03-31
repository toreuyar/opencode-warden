import { describe, test, expect, mock } from "bun:test"
import { OutputTriageEvaluator } from "../src/llm/output-triage.js"
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

function makeTriageConfig(overrides: Record<string, unknown> = {}): SecurityGuardConfig["llm"]["outputTriage"] {
  return {
    ...DEFAULT_CONFIG.llm.outputTriage,
    enabled: true,
    ...overrides,
  } as SecurityGuardConfig["llm"]["outputTriage"]
}

describe("OutputTriageEvaluator", () => {
  describe("isEnabled / isAvailable", () => {
    test("isEnabled returns config enabled state", () => {
      const config = makeTriageConfig({ enabled: true })
      const chain = new ProviderChain([makeProvider()])
      const triage = new OutputTriageEvaluator(config, chain)
      expect(triage.isEnabled()).toBe(true)
    })

    test("isEnabled returns false when disabled", () => {
      const config = makeTriageConfig({ enabled: false })
      const chain = new ProviderChain([makeProvider()])
      const triage = new OutputTriageEvaluator(config, chain)
      expect(triage.isEnabled()).toBe(false)
    })

    test("isAvailable delegates to provider chain", () => {
      const chain = new ProviderChain([makeProvider()])
      const triage = new OutputTriageEvaluator(makeTriageConfig(), chain)
      expect(triage.isAvailable()).toBe(true)
    })

    test("isAvailable returns false with empty chain", () => {
      const chain = new ProviderChain([])
      const triage = new OutputTriageEvaluator(makeTriageConfig(), chain)
      expect(triage.isAvailable()).toBe(false)
    })
  })

  describe("evaluate", () => {
    test("returns needsSanitization=false for safe command", async () => {
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => JSON.stringify({
        needsSanitization: false,
        reason: "listing command output is safe",
      }))
      const triage = new OutputTriageEvaluator(makeTriageConfig(), chain)
      const result = await triage.evaluate("bash", { command: "ls -la" })
      expect(result.needsSanitization).toBe(false)
      expect(result.reason).toContain("safe")
    })

    test("returns needsSanitization=true for risky command", async () => {
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => JSON.stringify({
        needsSanitization: true,
        reason: "cat on env file may contain secrets",
      }))
      const triage = new OutputTriageEvaluator(makeTriageConfig(), chain)
      const result = await triage.evaluate("bash", { command: "cat .env" })
      expect(result.needsSanitization).toBe(true)
    })

    test("throws on LLM failure (fail-closed)", async () => {
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => { throw new Error("connection refused") })
      const triage = new OutputTriageEvaluator(makeTriageConfig(), chain)
      await expect(triage.evaluate("bash", { command: "cat .env" })).rejects.toThrow("Command triage failed")
    })

    test("throws on unparseable response", async () => {
      const chain = new ProviderChain([makeProvider()])
      chain.call = mock(async () => "garbage output")
      const triage = new OutputTriageEvaluator(makeTriageConfig(), chain)
      await expect(triage.evaluate("bash", { command: "cat .env" })).rejects.toThrow("Could not parse")
    })
  })
})
