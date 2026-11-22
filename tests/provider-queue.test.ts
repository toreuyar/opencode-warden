import { describe, expect, test } from "bun:test"
import { ProviderChain } from "../src/llm/provider-chain.js"
import { providerQueue, ProviderOverloadError, retryDelay } from "../src/llm/request-queue.js"
import { ConversationContext } from "../src/llm/context.js"
import { DEFAULT_CONFIG, DEFAULT_REQUEST_POLICY } from "../src/config/defaults.js"
import { securityGuardConfigSchema } from "../src/config/schema.js"
import { SafetyEvaluator } from "../src/llm/safety-evaluator.js"
import type { LlmProviderConfig, LlmMessage } from "../src/types.js"

const messages = (content: string): LlmMessage[] => [{ role: "user", content }]
function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>((done) => { resolve = done })
  return { promise, resolve }
}
function provider(overrides: Partial<LlmProviderConfig> = {}): LlmProviderConfig {
  return {
    name: "gpu", baseUrl: "http://localhost:1234", model: "tiny",
    cooldown: 0, apiKey: "", timeout: 1000, temperature: 0, headers: {},
    healthCheckPath: "/models", completionsPath: `/${crypto.randomUUID()}`,
    requestPolicy: { concurrency: 1, maxQueueSize: 10, queueTimeoutMs: 1000, maxAttempts: 1 },
    ...overrides,
  }
}
const answer = (content: string) => Response.json({ choices: [{ message: { content } }] })

describe("process-wide provider admission", () => {
  test("separate chains/models share FIFO capacity and return each caller's own response", async () => {
    const started = deferred()
    const release = deferred()
    let active = 0
    let peak = 0
    const order: string[] = []
    const server = Bun.serve({ port: 0, async fetch(req) {
      const body = await req.json() as { messages: LlmMessage[] }
      const id = body.messages[0].content
      order.push(id)
      active++
      peak = Math.max(peak, active)
      if (id === "first") { started.resolve(); await release.promise }
      active--
      return answer(id)
    } })
    try {
      const config = provider({ baseUrl: `http://127.0.0.1:${server.port}` })
      const first = new ProviderChain([config])
      const second = new ProviderChain([{ ...config, name: "other", model: "different" }])
      const a = first.call(messages("first"))
      await started.promise
      const b = second.call(messages("second"))
      const c = first.call(messages("third"))
      expect(order).toEqual(["first"])
      release.resolve()
      expect(await Promise.all([a, b, c])).toEqual(["first", "second", "third"])
      expect(peak).toBe(1)
      expect(order).toEqual(["first", "second", "third"])
    } finally { release.resolve(); server.stop(true) }
  })

  test("queue overflow and expiry remove only the affected waiter", async () => {
    const config = provider({ requestPolicy: { concurrency: 1, maxQueueSize: 1 } })
    const queue = providerQueue(config)
    const release = await queue.acquire(1000)
    const waiting = queue.acquire(10)
    await expect(queue.acquire(1000)).rejects.toThrow("queue is full")
    await expect(waiting).rejects.toThrow("queue wait timed out")
    release()
    const next = await queue.acquire(1000)
    next()
    next() // Release is idempotent, cannot inflate capacity.
    const held = await queue.acquire(1000)
    await expect(queue.acquire(10)).rejects.toBeInstanceOf(ProviderOverloadError)
    held()
  })

  test("independent endpoints and configured parallel slots remain independent", async () => {
    const a = providerQueue(provider({ requestPolicy: { concurrency: 2, maxQueueSize: 0 } }))
    const b = providerQueue(provider())
    const releases = await Promise.all([a.acquire(100), a.acquire(100), b.acquire(100)])
    await expect(a.acquire(100)).rejects.toThrow("queue is full")
    for (const release of releases) release()
  })

  test("an unconfigured chain cannot bypass another chain's endpoint limit", async () => {
    const config = provider({ requestPolicy: { concurrency: 1, maxQueueSize: 0 } })
    const limited = providerQueue(config)
    const unlimited = providerQueue({ ...config, requestPolicy: undefined })
    const release = await limited.acquire(100)
    await expect(unlimited.acquire(100)).rejects.toThrow("queue is full")
    release()
  })

  test("queue wait is separate from inference timeout and errors release capacity", async () => {
    const server = Bun.serve({ port: 0, fetch: () => answer("ok") })
    try {
      const config = provider({ baseUrl: `http://127.0.0.1:${server.port}`, timeout: 100 })
      const release = await providerQueue(config).acquire(1000)
      const result = new ProviderChain([config]).call(messages("wait"))
      await Bun.sleep(130)
      release()
      expect(await result).toBe("ok")
      const bad = new ProviderChain([{ ...config, timeout: 1 }])
      // Validator failure is enough to verify release even after a rejected evaluation.
      await expect(bad.callValidated(messages("bad"), () => { throw new Error("invalid") })).rejects.toThrow()
      expect(await new ProviderChain([config]).call(messages("next"))).toBe("ok")
    } finally { server.stop(true) }
  })

  test("local overload falls back, or produces an explicit fail-closed evaluation", async () => {
    const config = provider({ requestPolicy: { concurrency: 1, maxQueueSize: 0, maxAttempts: 5 } })
    const release = await providerQueue(config).acquire(1000)
    try {
      const chain = new ProviderChain([config])
      const evaluator = new SafetyEvaluator({ ...DEFAULT_CONFIG.llm, enabled: true }, chain)
      const result = await evaluator.evaluate("read", { path: "/example" })
      expect(result.evaluationFailed).toBe(true)
      expect(result.providerOverloaded).toBe(true)
      expect(result.recommendation).toBe("block")
      expect(result.explanation).toContain("overloaded")
      const server = Bun.serve({ port: 0, fetch: () => answer("fallback") })
      try {
        const fallback = provider({ baseUrl: `http://127.0.0.1:${server.port}` })
        expect(await new ProviderChain([config, fallback]).call(messages("test"))).toBe("fallback")
      } finally { server.stop(true) }
    } finally { release() }
  })
})

describe("provider retry policy", () => {
  test("backoff starts at configured delay, doubles, jitters and caps", () => {
    expect(retryDelay(0, 5000, 30000, 0)).toBe(5000)
    expect(retryDelay(1, 5000, 30000, 0)).toBe(10000)
    expect(retryDelay(2, 5000, 30000, 1)).toBe(24000)
    expect(retryDelay(50, 5000, 30000, 1)).toBe(30000)
  })

  test("503 and empty answers retry, release their slot during backoff, and retain caller identity", async () => {
    const failed = deferred()
    const order: string[] = []
    let attempts = 0
    const server = Bun.serve({ port: 0, async fetch(req) {
      const body = await req.json() as { messages: LlmMessage[] }
      const id = body.messages[0].content
      order.push(id)
      if (id === "retry") {
        attempts++
        if (attempts === 1) { failed.resolve(); return new Response("", { status: 503 }) }
        if (attempts === 2) return answer("")
      }
      return answer(id)
    } })
    try {
      const config = provider({ baseUrl: `http://127.0.0.1:${server.port}`,
        requestPolicy: { concurrency: 1, maxAttempts: 3, initialDelayMs: 30, maxDelayMs: 100 } })
      const chain = new ProviderChain([config])
      const original = messages("retry")
      const result = chain.call(original)
      await failed.promise
      original[0].content = "mutated"
      expect(await chain.call(messages("other"))).toBe("other")
      expect(await result).toBe("retry")
      expect(order).toEqual(["retry", "other", "retry", "retry"])
    } finally { server.stop(true) }
  })

  test("maxAttempts=1 overrides legacy retryCount; exhaustion is finite and falls back", async () => {
    let calls = 0
    const server = Bun.serve({ port: 0, fetch() { calls++; return new Response("", { status: 500 }) } })
    try {
      const config = provider({ baseUrl: `http://127.0.0.1:${server.port}` })
      await expect(new ProviderChain([config]).call(messages("x"), { retryCount: 5 })).rejects.toThrow()
      expect(calls).toBe(1)
      const retry = { ...config, requestPolicy: { maxAttempts: 3, initialDelayMs: 1, maxDelayMs: 1 } }
      await expect(new ProviderChain([retry]).call(messages("x"))).rejects.toThrow()
      expect(calls).toBe(4)
    } finally { server.stop(true) }
  })

  test("authentication errors are not retried", async () => {
    let calls = 0
    const server = Bun.serve({ port: 0, fetch() { calls++; return new Response("", { status: 401 }) } })
    try {
      const config = provider({ baseUrl: `http://127.0.0.1:${server.port}`, requestPolicy: { maxAttempts: 5 } })
      await expect(new ProviderChain([config]).call(messages("x"))).rejects.toThrow()
      expect(calls).toBe(1)
    } finally { server.stop(true) }
  })

  test("a timed-out request retries with a fresh inference timeout", async () => {
    let calls = 0
    const finishStalled = deferred()
    const server = Bun.serve({ port: 0, async fetch() {
      calls++
      if (calls === 1) await finishStalled.promise
      return answer("recovered")
    } })
    try {
      const config = provider({ baseUrl: `http://127.0.0.1:${server.port}`, timeout: 50,
        requestPolicy: { concurrency: 1, maxAttempts: 2, initialDelayMs: 1, maxDelayMs: 1, recoveryDelayMs: 0 } })
      expect(await new ProviderChain([config]).call(messages("x"))).toBe("recovered")
      expect(calls).toBe(2)
    } finally { finishStalled.resolve(); server.stop(true) }
  })

  test("invalid safety verdicts retry, but genuine block verdicts never retry", async () => {
    let calls = 0
    const verdict = JSON.stringify({ safe: false, riskLevel: "high", riskDimensions: [],
      explanation: "dangerous", suggestedAlternative: "", recommendation: "block" })
    const server = Bun.serve({ port: 0, fetch() {
      calls++
      return answer(calls === 1 ? "invalid verdict" : verdict)
    } })
    try {
      const config = provider({ baseUrl: `http://127.0.0.1:${server.port}`,
        requestPolicy: { maxAttempts: 5, initialDelayMs: 1, maxDelayMs: 1 } })
      const evaluator = new SafetyEvaluator({ ...DEFAULT_CONFIG.llm, enabled: true }, new ProviderChain([config]))
      const result = await evaluator.evaluate("read", { path: "/example" })
      expect(calls).toBe(2)
      expect(result.recommendation).toBe("block")
      expect(result.evaluationFailed).toBeUndefined()
    } finally { server.stop(true) }
  })
})

test("overlapping conversation exchanges retain correct pairs and respect reset", () => {
  const context = new ConversationContext({ systemPrompt: "system", accumulate: true,
    detectionsOnly: false, maxPairs: 10, maxChars: 10000 })
  const a = context.beginExchange("a")
  const b = context.beginExchange("b")
  b.complete("answer b")
  a.complete("answer a")
  expect(context.getMessages().map((m) => m.content)).toEqual(["system", "b", "answer b", "a", "answer a"])
  const stale = context.beginExchange("stale")
  context.reset()
  stale.complete("late")
  expect(context.getMessages()).toHaveLength(1)
})

test("provider request policy defaults and validation", () => {
  expect(DEFAULT_REQUEST_POLICY.concurrency).toBe(0)
  expect(DEFAULT_REQUEST_POLICY.maxQueueSize).toBe(100)
  const valid = (requestPolicy: unknown) => securityGuardConfigSchema.safeParse({
    llm: { providers: [{ name: "gpu", requestPolicy }] },
  }).success
  expect(valid({ concurrency: 1, maxAttempts: 5, initialDelayMs: 30000 })).toBe(true)
  for (const invalid of [{ concurrency: -1 }, { concurrency: 0.5 }, { maxQueueSize: -1 },
    { totalTimeoutMs: 0 }, { recoveryDelayMs: -1 }, { totalTimeoutMs: 2147483648 },
    { maxAttempts: 0 }, { queueTimeoutMs: 0 }, { initialDelayMs: -1 }, { maxDelayMs: Infinity },
    { maxAttempts: 101 }, { unknown: true }]) expect(valid(invalid)).toBe(false)
})
