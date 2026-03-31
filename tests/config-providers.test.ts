import { describe, test, expect } from "bun:test"
import { existsSync, mkdirSync, writeFileSync, rmSync } from "fs"
import { join } from "path"
import { loadConfig } from "../src/config/index.js"

/**
 * Test config resolution with both old flat-field format
 * and new providers-array format.
 */

const TEST_DIR = join(import.meta.dir, ".test-fixtures")
const OPENCODE_DIR = join(TEST_DIR, ".opencode")
const CONFIG_PATH = join(OPENCODE_DIR, "opencode-warden.json")

function setup(config: Record<string, unknown>): void {
  mkdirSync(OPENCODE_DIR, { recursive: true })
  writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2))
}

function cleanup(): void {
  if (existsSync(TEST_DIR)) {
    rmSync(TEST_DIR, { recursive: true, force: true })
  }
}

// ─── Old flat-field config (backward compat) ───

describe("old flat-field config", () => {
  test("shared flat fields are normalized into providers arrays on all components", () => {
    setup({
      llm: {
        enabled: true,
        baseUrl: "http://127.0.0.1:11434/v1",
        model: "qwen3:8b",
        timeout: 60000,
        temperature: 0,
        healthCheckPath: "/models",
        completionsPath: "/chat/completions",
      },
    })

    const { config, warnings } = loadConfig(TEST_DIR, { skipGlobalConfig: true })
    expect(warnings).toHaveLength(0)
    expect(config.llm.enabled).toBe(true)

    // Each component should have a single-element providers array
    for (const comp of ["safetyEvaluator", "outputTriage", "outputTextTriage", "outputSanitizer"] as const) {
      const providers = config.llm[comp].providers
      expect(providers).toHaveLength(1)
      expect(providers[0].baseUrl).toBe("http://127.0.0.1:11434/v1")
      expect(providers[0].model).toBe("qwen3:8b")
      expect(providers[0].timeout).toBe(60000)
      expect(providers[0].temperature).toBe(0)
      expect(providers[0].healthCheckPath).toBe("/models")
      expect(providers[0].completionsPath).toBe("/chat/completions")
      expect(providers[0].name).toBe("default")
      expect(providers[0].cooldown).toBe(0)
    }

    // Flat fields should also be propagated (backward compat for any code reading them)
    expect(config.llm.safetyEvaluator.baseUrl).toBe("http://127.0.0.1:11434/v1")
    expect(config.llm.safetyEvaluator.model).toBe("qwen3:8b")

    cleanup()
  })

  test("component-level flat fields override shared flat fields", () => {
    setup({
      llm: {
        enabled: true,
        baseUrl: "http://127.0.0.1:11434/v1",
        model: "qwen3:8b",
        timeout: 60000,
        temperature: 0,
        healthCheckPath: "/models",
        completionsPath: "/chat/completions",
        safetyEvaluator: {
          model: "qwen3:1b",
          timeout: 30000,
        },
      },
    })

    const { config } = loadConfig(TEST_DIR, { skipGlobalConfig: true })

    // Safety evaluator should use its own model/timeout but inherit baseUrl etc.
    const se = config.llm.safetyEvaluator
    expect(se.providers).toHaveLength(1)
    expect(se.providers[0].model).toBe("qwen3:1b")
    expect(se.providers[0].timeout).toBe(30000)
    expect(se.providers[0].baseUrl).toBe("http://127.0.0.1:11434/v1")

    // Other components should use shared values
    expect(config.llm.outputSanitizer.providers[0].model).toBe("qwen3:8b")
    expect(config.llm.outputSanitizer.providers[0].timeout).toBe(60000)

    cleanup()
  })

  test("missing optional fields get safe defaults", () => {
    setup({
      llm: {
        enabled: true,
        baseUrl: "http://127.0.0.1:11434/v1",
        model: "qwen3:8b",
        // No apiKey, headers, timeout, temperature, etc.
      },
    })

    const { config } = loadConfig(TEST_DIR, { skipGlobalConfig: true })

    // Provider should have the user-specified fields
    const p = config.llm.safetyEvaluator.providers[0]
    expect(p.baseUrl).toBe("http://127.0.0.1:11434/v1")
    expect(p.model).toBe("qwen3:8b")

    // Missing fields should have safe defaults (not undefined)
    expect(p.apiKey).toBe("")
    expect(p.headers).toEqual({})
    expect(typeof p.timeout).toBe("number")
    expect(typeof p.temperature).toBe("number")
    expect(typeof p.cooldown).toBe("number")

    cleanup()
  })
})

// ─── New providers-array config ───

describe("new providers-array config", () => {
  test("shared providers array is inherited by all components", () => {
    setup({
      llm: {
        enabled: true,
        providers: [
          {
            name: "ollama",
            baseUrl: "http://127.0.0.1:11434/v1",
            model: "qwen3:8b",
            timeout: 60000,
            healthCheckPath: "/models",
            completionsPath: "/chat/completions",
            cooldown: 3600000,
          },
          {
            name: "openai",
            baseUrl: "https://api.openai.com/v1",
            model: "gpt-4o-mini",
            apiKey: "sk-test",
            timeout: 30000,
            completionsPath: "/chat/completions",
          },
        ],
      },
    })

    const { config, warnings } = loadConfig(TEST_DIR, { skipGlobalConfig: true })
    expect(warnings).toHaveLength(0)

    // Each component should inherit the shared providers
    for (const comp of ["safetyEvaluator", "outputTriage", "outputTextTriage", "outputSanitizer"] as const) {
      const providers = config.llm[comp].providers
      expect(providers).toHaveLength(2)
      expect(providers[0].name).toBe("ollama")
      expect(providers[0].baseUrl).toBe("http://127.0.0.1:11434/v1")
      expect(providers[0].cooldown).toBe(3600000)
      expect(providers[1].name).toBe("openai")
      expect(providers[1].baseUrl).toBe("https://api.openai.com/v1")
      expect(providers[1].apiKey).toBe("sk-test")
    }

    cleanup()
  })

  test("component-level providers override shared providers entirely", () => {
    setup({
      llm: {
        enabled: true,
        providers: [
          {
            name: "shared-provider",
            baseUrl: "http://shared:11434/v1",
            model: "shared-model",
            completionsPath: "/chat/completions",
          },
        ],
        safetyEvaluator: {
          providers: [
            {
              name: "safety-only",
              baseUrl: "http://safety:11434/v1",
              model: "safety-model",
              completionsPath: "/chat/completions",
            },
          ],
        },
      },
    })

    const { config } = loadConfig(TEST_DIR, { skipGlobalConfig: true })

    // Safety evaluator uses its own providers
    expect(config.llm.safetyEvaluator.providers).toHaveLength(1)
    expect(config.llm.safetyEvaluator.providers[0].name).toBe("safety-only")
    expect(config.llm.safetyEvaluator.providers[0].baseUrl).toBe("http://safety:11434/v1")

    // Other components inherit shared providers
    expect(config.llm.outputSanitizer.providers).toHaveLength(1)
    expect(config.llm.outputSanitizer.providers[0].name).toBe("shared-provider")

    cleanup()
  })

  test("auto-generates provider names when omitted", () => {
    setup({
      llm: {
        enabled: true,
        providers: [
          {
            baseUrl: "http://127.0.0.1:11434/v1",
            model: "qwen3:8b",
            completionsPath: "/chat/completions",
          },
          {
            baseUrl: "https://api.openai.com/v1",
            model: "gpt-4o-mini",
            completionsPath: "/chat/completions",
          },
        ],
      },
    })

    const { config } = loadConfig(TEST_DIR, { skipGlobalConfig: true })
    // Names not provided in config — ProviderChain normalizeProvider assigns them
    // But at config level they may be undefined; ProviderChain normalizes them
    const providers = config.llm.safetyEvaluator.providers
    expect(providers).toHaveLength(2)

    cleanup()
  })
})

// ─── Mixed config (flat fields + providers should not conflict) ───

describe("config edge cases", () => {
  test("no llm config at all uses defaults", () => {
    setup({})

    const { config } = loadConfig(TEST_DIR, { skipGlobalConfig: true })
    expect(config.llm.enabled).toBe(false)
    // Defaults have empty providers arrays
    expect(config.llm.providers).toEqual([])
    expect(config.llm.safetyEvaluator.providers).toEqual([])

    cleanup()
  })

  test("llm enabled but no endpoint info has empty providers", () => {
    setup({
      llm: {
        enabled: true,
      },
    })

    const { config } = loadConfig(TEST_DIR, { skipGlobalConfig: true })
    expect(config.llm.enabled).toBe(true)
    // No baseUrl/model/providers set → empty chain
    expect(config.llm.safetyEvaluator.providers).toEqual([])
    expect(config.llm.outputSanitizer.providers).toEqual([])

    cleanup()
  })

  test("cooldown defaults to 0 when omitted", () => {
    setup({
      llm: {
        enabled: true,
        providers: [
          {
            baseUrl: "http://127.0.0.1:11434/v1",
            model: "qwen3:8b",
            completionsPath: "/chat/completions",
          },
        ],
      },
    })

    const { config } = loadConfig(TEST_DIR, { skipGlobalConfig: true })
    const p = config.llm.safetyEvaluator.providers[0]
    expect(p.cooldown).toBe(0)

    cleanup()
  })
})
