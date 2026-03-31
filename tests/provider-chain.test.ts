import { describe, test, expect, mock, beforeEach } from "bun:test"
import { ProviderChain } from "../src/llm/provider-chain.js"
import { LlmApiError } from "../src/llm/client.js"
import type { LlmProviderConfig, LlmMessage } from "../src/types.js"

// ─── Helpers ───

function makeProvider(overrides: Partial<LlmProviderConfig> = {}): LlmProviderConfig {
  return {
    name: "test-provider",
    cooldown: 0,
    baseUrl: "http://localhost:11434/v1",
    model: "test-model",
    apiKey: "",
    timeout: 10000,
    temperature: 0,
    headers: {},
    healthCheckPath: "/models",
    completionsPath: "/chat/completions",
    ...overrides,
  }
}

const MESSAGES: LlmMessage[] = [
  { role: "system", content: "You are a test." },
  { role: "user", content: "Hello" },
]

// ─── normalizeProvider (via constructor) ───

describe("ProviderChain normalization", () => {
  test("fills missing fields with safe defaults", () => {
    // Pass a minimal provider with only baseUrl and model
    const chain = new ProviderChain(
      [{ baseUrl: "http://localhost:11434/v1", model: "qwen3:8b" } as any],
    )
    const info = chain.getProviderInfo()
    expect(info).toHaveLength(1)
    // Should have auto-generated name
    expect(info[0].name).toBe("provider-1")
    expect(info[0].onCooldown).toBe(false)
  })

  test("preserves user-provided name", () => {
    const chain = new ProviderChain([makeProvider({ name: "my-ollama" })])
    const info = chain.getProviderInfo()
    expect(info[0].name).toBe("my-ollama")
  })

  test("auto-generates names by index when omitted", () => {
    const chain = new ProviderChain([
      makeProvider({ name: "" }),
      makeProvider({ name: "" }),
    ])
    const info = chain.getProviderInfo()
    expect(info[0].name).toBe("provider-1")
    expect(info[1].name).toBe("provider-2")
  })

  test("handles empty providers array", () => {
    const chain = new ProviderChain([])
    expect(chain.isAvailable()).toBe(false)
    expect(chain.getProviderInfo()).toEqual([])
  })

  test("handles undefined headers/apiKey without crashing", () => {
    // Simulate what flatFieldsToProvider produces for old configs missing apiKey/headers
    const chain = new ProviderChain([
      {
        baseUrl: "http://localhost:11434/v1",
        model: "qwen3:8b",
        timeout: 60000,
        completionsPath: "/chat/completions",
        healthCheckPath: "/models",
        // Missing: apiKey, headers, temperature, name, cooldown
      } as any,
    ])
    const info = chain.getProviderInfo()
    expect(info).toHaveLength(1)
    expect(info[0].name).toBe("provider-1")
    // The key thing: this should NOT throw
  })
})

// ─── isAvailable ───

describe("ProviderChain.isAvailable", () => {
  test("returns true when providers exist and none on cooldown", () => {
    const chain = new ProviderChain([makeProvider()])
    expect(chain.isAvailable()).toBe(true)
  })

  test("returns false for empty providers", () => {
    const chain = new ProviderChain([])
    expect(chain.isAvailable()).toBe(false)
  })
})

// ─── Fallback & cooldown logic (using mock fetch) ───

describe("ProviderChain.call fallback logic", () => {
  let originalFetch: typeof globalThis.fetch

  beforeEach(() => {
    originalFetch = globalThis.fetch
  })

  function restoreFetch() {
    globalThis.fetch = originalFetch
  }

  test("succeeds with first provider on normal response", async () => {
    globalThis.fetch = mock(async () =>
      new Response(
        JSON.stringify({
          choices: [{ message: { content: "ok" } }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    ) as any

    const chain = new ProviderChain([makeProvider({ name: "p1" })])
    const result = await chain.call(MESSAGES, { componentName: "test" })
    expect(result).toBe("ok")

    restoreFetch()
  })

  test("falls back to second provider on 429 from first", async () => {
    let callCount = 0
    globalThis.fetch = mock(async () => {
      callCount++
      if (callCount === 1) {
        return new Response("rate limited", { status: 429 })
      }
      return new Response(
        JSON.stringify({
          choices: [{ message: { content: "fallback-ok" } }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )
    }) as any

    const chain = new ProviderChain([
      makeProvider({ name: "primary", cooldown: 60000 }),
      makeProvider({ name: "secondary" }),
    ])
    const result = await chain.call(MESSAGES, { componentName: "test" })
    expect(result).toBe("fallback-ok")
    expect(callCount).toBe(2)

    restoreFetch()
  })

  test("falls back on 402 (payment required)", async () => {
    let callCount = 0
    globalThis.fetch = mock(async () => {
      callCount++
      if (callCount === 1) {
        return new Response("payment required", { status: 402 })
      }
      return new Response(
        JSON.stringify({
          choices: [{ message: { content: "fallback-ok" } }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )
    }) as any

    const chain = new ProviderChain([
      makeProvider({ name: "primary" }),
      makeProvider({ name: "secondary" }),
    ])
    const result = await chain.call(MESSAGES, { componentName: "test" })
    expect(result).toBe("fallback-ok")

    restoreFetch()
  })

  test("falls back on 503 (overloaded)", async () => {
    let callCount = 0
    globalThis.fetch = mock(async () => {
      callCount++
      if (callCount === 1) {
        return new Response("overloaded", { status: 503 })
      }
      return new Response(
        JSON.stringify({
          choices: [{ message: { content: "fallback-ok" } }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )
    }) as any

    const chain = new ProviderChain([
      makeProvider({ name: "primary" }),
      makeProvider({ name: "secondary" }),
    ])
    const result = await chain.call(MESSAGES, { componentName: "test" })
    expect(result).toBe("fallback-ok")

    restoreFetch()
  })

  test("falls back on transient error (network failure)", async () => {
    let callCount = 0
    globalThis.fetch = mock(async () => {
      callCount++
      if (callCount === 1) {
        throw new Error("ECONNREFUSED")
      }
      return new Response(
        JSON.stringify({
          choices: [{ message: { content: "fallback-ok" } }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )
    }) as any

    const chain = new ProviderChain([
      makeProvider({ name: "primary" }),
      makeProvider({ name: "secondary" }),
    ])
    const result = await chain.call(MESSAGES, { componentName: "test" })
    expect(result).toBe("fallback-ok")

    restoreFetch()
  })

  test("throws when all providers fail (fail-closed)", async () => {
    globalThis.fetch = mock(async () => {
      throw new Error("ECONNREFUSED")
    }) as any

    const chain = new ProviderChain([
      makeProvider({ name: "p1" }),
      makeProvider({ name: "p2" }),
    ])

    await expect(chain.call(MESSAGES, { componentName: "test" })).rejects.toThrow(
      "All LLM providers failed",
    )

    restoreFetch()
  })

  test("skips provider on cooldown after exhaustion", async () => {
    let callCount = 0
    const urls: string[] = []

    globalThis.fetch = mock(async (req: Request) => {
      callCount++
      urls.push(new URL(req.url).host)
      if (callCount === 1) {
        // First call: primary returns 429
        return new Response("rate limited", { status: 429 })
      }
      // All subsequent calls succeed
      return new Response(
        JSON.stringify({
          choices: [{ message: { content: `response-${callCount}` } }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )
    }) as any

    const chain = new ProviderChain([
      makeProvider({ name: "primary", baseUrl: "http://primary:11434/v1", cooldown: 60000 }),
      makeProvider({ name: "secondary", baseUrl: "http://secondary:11434/v1" }),
    ])

    // First call: primary exhausted (429), falls back to secondary
    const r1 = await chain.call(MESSAGES, { componentName: "test" })
    expect(r1).toBe("response-2")
    expect(callCount).toBe(2)

    // Second call: primary should be skipped (on cooldown), goes straight to secondary
    const r2 = await chain.call(MESSAGES, { componentName: "test" })
    expect(r2).toBe("response-3")
    expect(callCount).toBe(3)

    // Verify primary was only called once (the 429), then skipped
    expect(urls[0]).toBe("primary:11434")
    expect(urls[1]).toBe("secondary:11434")
    expect(urls[2]).toBe("secondary:11434") // Skipped primary

    restoreFetch()
  })

  test("cooldown=0 means always retry", async () => {
    let callCount = 0

    globalThis.fetch = mock(async () => {
      callCount++
      if (callCount <= 2) {
        // First two calls: return 429
        return new Response("rate limited", { status: 429 })
      }
      return new Response(
        JSON.stringify({
          choices: [{ message: { content: "ok" } }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )
    }) as any

    const chain = new ProviderChain([
      makeProvider({ name: "primary", cooldown: 0 }),
    ])

    // First call: 429 with cooldown=0 → no cooldown set, but still fails this call
    await expect(chain.call(MESSAGES)).rejects.toThrow("All LLM providers failed")

    // Second call: should retry primary (cooldown=0 means always try)
    await expect(chain.call(MESSAGES)).rejects.toThrow("All LLM providers failed")

    // Third call: succeeds
    const result = await chain.call(MESSAGES)
    expect(result).toBe("ok")
    expect(callCount).toBe(3)

    restoreFetch()
  })

  test("successful call resets cooldown for that provider", async () => {
    let callCount = 0
    const calledProviders: string[] = []

    globalThis.fetch = mock(async (req: Request) => {
      callCount++
      const host = new URL(req.url).host
      calledProviders.push(host)

      if (callCount === 1) {
        // First request to primary: 429
        return new Response("rate limited", { status: 429 })
      }
      // Everything else succeeds
      return new Response(
        JSON.stringify({
          choices: [{ message: { content: `ok-${callCount}` } }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )
    }) as any

    const chain = new ProviderChain([
      makeProvider({ name: "primary", baseUrl: "http://primary:11434/v1", cooldown: 100 }),
      makeProvider({ name: "secondary", baseUrl: "http://secondary:11434/v1" }),
    ])

    // Call 1: primary 429 → fallback to secondary
    await chain.call(MESSAGES)
    expect(calledProviders).toEqual(["primary:11434", "secondary:11434"])

    // Wait for cooldown to expire
    await new Promise(resolve => setTimeout(resolve, 150))

    // Call 2: primary should be tried again (cooldown expired)
    await chain.call(MESSAGES)
    expect(calledProviders[2]).toBe("primary:11434") // Primary retried

    restoreFetch()
  })

  test("non-exhaustion HTTP errors (e.g. 500) do NOT set cooldown", async () => {
    let callCount = 0
    const calledProviders: string[] = []

    globalThis.fetch = mock(async (req: Request) => {
      callCount++
      calledProviders.push(new URL(req.url).host)

      if (calledProviders[calledProviders.length - 1] === "primary:11434" && callCount <= 2) {
        return new Response("internal error", { status: 500 })
      }
      return new Response(
        JSON.stringify({
          choices: [{ message: { content: "ok" } }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )
    }) as any

    const chain = new ProviderChain([
      makeProvider({ name: "primary", baseUrl: "http://primary:11434/v1", cooldown: 60000 }),
      makeProvider({ name: "secondary", baseUrl: "http://secondary:11434/v1" }),
    ])

    // Call 1: primary 500 → fallback to secondary
    await chain.call(MESSAGES)

    // Call 2: primary should still be tried (500 is NOT an exhaustion code)
    await chain.call(MESSAGES)
    expect(calledProviders[2]).toBe("primary:11434") // Not skipped

    restoreFetch()
  })
})

// ─── LlmApiError ───

describe("LlmApiError", () => {
  test("has statusCode property", () => {
    const err = new LlmApiError(429, "Rate limited")
    expect(err.statusCode).toBe(429)
    expect(err.message).toBe("Rate limited")
    expect(err.name).toBe("LlmApiError")
    expect(err instanceof Error).toBe(true)
    expect(err instanceof LlmApiError).toBe(true)
  })
})

// ─── healthCheck ───

describe("ProviderChain.healthCheck", () => {
  let originalFetch: typeof globalThis.fetch

  beforeEach(() => {
    originalFetch = globalThis.fetch
  })

  function restoreFetch() {
    globalThis.fetch = originalFetch
  }

  test("returns true if any provider responds OK", async () => {
    let callCount = 0
    globalThis.fetch = mock(async () => {
      callCount++
      if (callCount === 1) throw new Error("ECONNREFUSED")
      return new Response("ok", { status: 200 })
    }) as any

    const chain = new ProviderChain([
      makeProvider({ name: "down" }),
      makeProvider({ name: "up" }),
    ])
    const healthy = await chain.healthCheck()
    expect(healthy).toBe(true)

    restoreFetch()
  })

  test("returns false if all providers fail", async () => {
    globalThis.fetch = mock(async () => {
      throw new Error("ECONNREFUSED")
    }) as any

    const chain = new ProviderChain([
      makeProvider({ name: "down1" }),
      makeProvider({ name: "down2" }),
    ])
    const healthy = await chain.healthCheck()
    expect(healthy).toBe(false)

    restoreFetch()
  })

  test("returns false for empty providers", async () => {
    const chain = new ProviderChain([])
    const healthy = await chain.healthCheck()
    expect(healthy).toBe(false)
  })
})
