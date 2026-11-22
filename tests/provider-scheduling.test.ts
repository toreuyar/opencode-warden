import { describe, expect, test } from "bun:test"
import { ProviderChain } from "../src/llm/provider-chain.js"
import { providerQueueStats, registerProviderQueues } from "../src/llm/request-queue.js"
import { createRequestLifecycle, LlmRequestError, withLlmRequest } from "../src/llm/request-context.js"
import { parseRetryAfter } from "../src/llm/client.js"
import type { LlmMessage, LlmProviderConfig } from "../src/types.js"
import { withholdExecuteAfter } from "../src/hooks/v2-adapters.js"
import { LlmChatLogger } from "../src/audit/llm-chat-logger.js"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const messages: LlmMessage[] = [{ role: "user", content: "synthetic test" }]
const answer = () => Response.json({ choices: [{ message: { content: "ok" } }] })
const provider = (baseUrl = "http://localhost:1"): LlmProviderConfig => ({
  name: "test", baseUrl, model: "test", cooldown: 0, apiKey: "", timeout: 1000,
  temperature: 0, headers: {}, completionsPath: `/${crypto.randomUUID()}`, healthCheckPath: "/models",
  requestPolicy: { concurrency: 1, totalTimeoutMs: 1000, queueTimeoutMs: 1000, recoveryDelayMs: 0, maxAttempts: 1 },
})
function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>((done) => { resolve = done })
  return { promise, resolve }
}

describe("cancellation and overall deadlines", () => {
  test("deadline withholding removes every success and error output channel", () => {
    const completed = { status: "completed" as const, tool: "read", sessionID: "s", id: "c", input: {},
      result: { content: "raw", output: { secret: "raw" }, metadata: { title: "raw" } },
    }
    const failed = { status: "error" as const, tool: "read", sessionID: "s", id: "c", input: {},
      error: { message: "raw", error: { message: "raw cause" }, metadata: { title: "raw" } },
    }
    for (const event of [completed, failed]) {
      withholdExecuteAfter(event, "Warden: LLM evaluation deadline exceeded")
      expect(JSON.stringify(event)).not.toContain("raw")
      expect(JSON.stringify(event)).toContain("[BLOCKED]")
    }
  })

  test("cancelled waiters are removed without affecting the active request", async () => {
    const registration = registerProviderQueues([provider()])
    const queue = registration.queues[0]
    const release = await queue.acquire(1000)
    const cancel = new AbortController()
    const waiting = queue.acquire(1000, cancel.signal)
    expect(queue.snapshot().waiting).toBe(1)
    cancel.abort()
    await expect(waiting).rejects.toThrow("cancelled")
    expect(queue.snapshot().waiting).toBe(0)
    expect(queue.snapshot().active).toBe(1)
    expect(queue.snapshot().cancelledCount).toBe(1)
    release()
    registration.dispose()
  })

  test("cancellation during inference aborts transport and never retries or falls back", async () => {
    const entered = deferred()
    const finish = deferred()
    let calls = 0
    const server = Bun.serve({ port: 0, async fetch() { calls++; entered.resolve(); await finish.promise; return answer() } })
    const config = provider(`http://127.0.0.1:${server.port}`)
    config.requestPolicy!.maxAttempts = 5
    const chain = new ProviderChain([config, config])
    try {
      const cancel = new AbortController()
      const result = chain.call(messages, { signal: cancel.signal })
      await entered.promise
      cancel.abort()
      await expect(result).rejects.toThrow("cancelled")
      expect(calls).toBe(1)
    } finally { finish.resolve(); chain.dispose(); server.stop(true) }
  })

  test("cancellation interrupts retry backoff", async () => {
    const backingOff = deferred()
    let calls = 0
    const server = Bun.serve({ port: 0, fetch() { calls++; return new Response("", { status: 500 }) } })
    const config = provider(`http://127.0.0.1:${server.port}`)
    config.requestPolicy = { ...config.requestPolicy, maxAttempts: 5, initialDelayMs: 5000 }
    const chain = new ProviderChain([config], (log) => { if (log.includes('"phase":"backoff"')) backingOff.resolve() })
    try {
      const cancel = new AbortController()
      const result = chain.call(messages, { signal: cancel.signal })
      await backingOff.promise
      cancel.abort()
      await expect(result).rejects.toThrow("cancelled")
      expect(calls).toBe(1)
      expect(providerQueueStats().flatMap((queue) => queue.retries)).toEqual([])
    } finally { chain.dispose(); server.stop(true) }
  })

  test("the overall deadline includes queue wait and prevents fallback", async () => {
    const config = provider()
    config.requestPolicy!.totalTimeoutMs = 20
    const registration = registerProviderQueues([config])
    const release = await registration.queues[0].acquire(1000)
    const chain = new ProviderChain([config, provider()])
    try {
      await expect(chain.call(messages)).rejects.toThrow("deadline exceeded")
      expect(registration.queues[0].snapshot().waiting).toBe(0)
    } finally { release(); chain.dispose(); registration.dispose() }
  })

  test("a parent evaluation budget is shared across multiple component calls", async () => {
    let calls = 0
    const server = Bun.serve({ port: 0, async fetch() { calls++; await Bun.sleep(40); return answer() } })
    const chain = new ProviderChain([provider(`http://127.0.0.1:${server.port}`)])
    try {
      await expect(withLlmRequest({ timeoutMs: 70 }, async () => {
        await chain.call(messages)
        await chain.call(messages)
      })).rejects.toThrow("deadline exceeded")
      expect(calls).toBe(2)
    } finally { chain.dispose(); server.stop(true) }
  })

  test("lifecycle cancellation is session-scoped and future work gets a fresh signal", () => {
    const lifecycle = createRequestLifecycle()
    const a = lifecycle.signal("a")
    const b = lifecycle.signal("b")
    lifecycle.cancel("a")
    expect(a.aborted).toBe(true)
    expect(b.aborted).toBe(false)
    expect(lifecycle.signal("a").aborted).toBe(false)
    lifecycle.dispose()
    expect(b.aborted).toBe(true)
    expect(lifecycle.signal("new").aborted).toBe(true)
  })
})

describe("recovery, server backoff and live limits", () => {
  test("two real streamed responses through a shared logger stay paired and individually tagged", async () => {
    const directory = mkdtempSync(join(tmpdir(), "warden-streams-"))
    const path = join(directory, "chat.log")
    let entered = 0
    const both = deferred()
    const server = Bun.serve({ port: 0, async fetch(request) {
      const body = await request.json() as { messages: LlmMessage[] }
      const marker = body.messages[0].content
      entered++
      if (entered === 2) both.resolve()
      await both.promise
      return new Response(`data: ${JSON.stringify({ choices: [{ delta: { content: marker }, finish_reason: "stop" }] })}\n\ndata: [DONE]\n\n`,
        { headers: { "Content-Type": "text/event-stream" } })
    } })
    const config = provider(`http://127.0.0.1:${server.port}`)
    config.requestPolicy!.concurrency = 2
    const logger = new LlmChatLogger({ filePath: path, maxFileSize: 100000, maxFiles: 2 })
    const chain = new ProviderChain([config], undefined, logger)
    try {
      const results = await Promise.all(["FIRST", "SECOND"].map((content) => chain.call([{ role: "user", content }])))
      expect(results).toEqual(["FIRST", "SECOND"])
      const log = readFileSync(path, "utf8")
      const footers = log.split("\n").filter((line) => line.includes("◼"))
      expect(footers).toHaveLength(2)
      expect(footers.every((line) => line.includes("1 tok"))).toBe(true)
      const attempts = new Set(footers.map((line) => line.match(/attempt=([^\]]+)/)?.[1]))
      expect(attempts.size).toBe(2)
    } finally { both.resolve(); chain.dispose(); server.stop(true); rmSync(directory, { recursive: true, force: true }) }
  })

  test("recovery pause applies to other callers after a timeout", async () => {
    let calls = 0
    let secondStarted = 0
    const finish = deferred()
    const server = Bun.serve({ port: 0, async fetch() {
      calls++
      if (calls === 1) await finish.promise
      else secondStarted = Date.now()
      return answer()
    } })
    const config = provider(`http://127.0.0.1:${server.port}`)
    config.timeout = 20
    config.requestPolicy!.recoveryDelayMs = 70
    const chain = new ProviderChain([config])
    try {
      await expect(chain.call(messages)).rejects.toThrow("timed out")
      const failedAt = Date.now()
      expect(await chain.call(messages)).toBe("ok")
      expect(secondStarted - failedAt).toBeGreaterThanOrEqual(55)
    } finally { finish.resolve(); chain.dispose(); server.stop(true) }
  })

  test("Retry-After parsing supports delta seconds and dates", () => {
    expect(parseRetryAfter("2")).toBe(2000)
    expect(parseRetryAfter("0.05")).toBe(50)
    expect(parseRetryAfter("Wed, 21 Oct 2015 07:28:00 GMT", Date.parse("Wed, 21 Oct 2015 07:27:00 GMT"))).toBe(60000)
    expect(parseRetryAfter("garbage")).toBeUndefined()
    expect(parseRetryAfter(null)).toBeUndefined()
  })

  test("Retry-After delays every caller sharing an endpoint, even without retries", async () => {
    let calls = 0
    let secondStarted = 0
    const server = Bun.serve({ port: 0, fetch() {
      calls++
      if (calls === 1) return new Response("", { status: 503, headers: { "Retry-After": "0.08" } })
      secondStarted = Date.now()
      return answer()
    } })
    const chain = new ProviderChain([provider(`http://127.0.0.1:${server.port}`)])
    try {
      await expect(chain.call(messages)).rejects.toThrow()
      const failedAt = Date.now()
      expect(await chain.call(messages)).toBe("ok")
      expect(secondStarted - failedAt).toBeGreaterThanOrEqual(60)
    } finally { chain.dispose(); server.stop(true) }
  })

  test("Retry-After cannot extend the overall deadline", async () => {
    let calls = 0
    const server = Bun.serve({ port: 0, fetch() { calls++; return new Response("", { status: 429, headers: { "Retry-After": "60" } }) } })
    const config = provider(`http://127.0.0.1:${server.port}`)
    config.requestPolicy = { ...config.requestPolicy, maxAttempts: 5, totalTimeoutMs: 30 }
    const chain = new ProviderChain([config])
    try {
      await expect(chain.call(messages)).rejects.toBeInstanceOf(LlmRequestError)
      expect(calls).toBe(1)
    } finally { chain.dispose(); server.stop(true) }
  })

  test("raising drains waiters; lowering lets active requests finish", async () => {
    const registration = registerProviderQueues([provider()])
    const queue = registration.queues[0]
    const first = await queue.acquire(1000)
    const waiting = queue.acquire(1000)
    registration.update(0, { concurrency: 2 })
    const second = await waiting
    expect(queue.snapshot().active).toBe(2)
    registration.update(0, { concurrency: 1 })
    let admitted = false
    const third = queue.acquire(1000).then((release) => { admitted = true; return release })
    first()
    await Promise.resolve()
    expect(admitted).toBe(false)
    second()
    ;(await third)()
    registration.dispose()
  })

  test("reload replaces ownership; stale disposal cannot remove the new limit", async () => {
    const config = provider()
    const owner = crypto.randomUUID()
    const old = registerProviderQueues([config], owner)
    const current = registerProviderQueues([{ ...config, requestPolicy: { concurrency: 2 } }], owner)
    expect(() => old.update(0, { concurrency: 10 })).toThrow("replaced")
    old.dispose()
    const queue = current.queues[0]
    expect(queue.snapshot().concurrency).toBe(2)
    const a = await queue.acquire(100)
    const b = await queue.acquire(100)
    expect(queue.snapshot().active).toBe(2)
    a()
    b()
    current.dispose()
  })
})
