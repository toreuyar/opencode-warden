/**
 * Opt-in live test: bun scripts/provider-concurrency-probe.ts BASE_URL MODEL
 * Sends four short queued requests, cancels one streamed generation, then
 * checks immediate recovery. Synthetic prompts only. No config files are read.
 */
import { ProviderChain } from "../src/llm/provider-chain.js"
import { providerQueueStats } from "../src/llm/request-queue.js"
import type { LlmProviderConfig } from "../src/types.js"

const [baseUrl, model] = Bun.argv.slice(2)
if (!baseUrl || !model) throw new Error("Usage: bun scripts/provider-concurrency-probe.ts BASE_URL MODEL")
const apiKey = process.env.WARDEN_PROBE_API_KEY ?? ""
const headers = { "Content-Type": "application/json", ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}) }
const config: LlmProviderConfig = {
  name: "live-probe", baseUrl: baseUrl.replace(/\/+$/, ""), model, apiKey,
  timeout: 60000, cooldown: 0, temperature: 0, maxTokens: 512, headers: {},
  completionsPath: "/chat/completions", healthCheckPath: "/models",
  requestPolicy: { concurrency: 1, maxQueueSize: 10, queueTimeoutMs: 120000,
    totalTimeoutMs: 180000, recoveryDelayMs: 5000, maxAttempts: 1 },
}
let peak = 0
let inferenceCalls = 0
const log = (text: string) => {
  if (!text.startsWith("LLM scheduling ")) return
  const event = JSON.parse(text.slice("LLM scheduling ".length))
  peak = Math.max(peak, event.active)
  if (event.phase === "inference") inferenceCalls++
}
const chains = [new ProviderChain([config], log), new ProviderChain([config], log)]
try {
  const start = Date.now()
  const results = await Promise.allSettled(["ALPHA", "BRAVO", "CHARLIE", "DELTA"].map(async (marker, i) => {
    const text = await chains[i % 2].call([
      { role: "system", content: "Return only the requested marker, without explanation." },
      { role: "user", content: `Reply with exactly ${marker}.` },
    ])
    return { marker, matches: text.trim() === marker }
  }))
  console.log(JSON.stringify({ phase: "queued-burst", elapsedMs: Date.now() - start, peak, inferenceCalls,
    results: results.map((result) => result.status === "fulfilled"
      ? result.value : { error: result.reason instanceof Error ? result.reason.message : "failed" }) }))
  if (peak !== 1 || results.some((result) => result.status === "rejected" || !result.value.matches)) throw new Error("Queued burst failed")

  // Intentionally bypass the scheduler once to measure real backend disconnect
  // behavior without the configured recovery pause hiding it.
  const cancel = new AbortController()
  const timeout = setTimeout(() => cancel.abort(), 60000)
  let receivedData = false
  let streamFinishedBeforeAbort = false
  try {
    const response = await fetch(`${config.baseUrl}/chat/completions`, {
      method: "POST", headers, signal: cancel.signal,
      body: JSON.stringify({ model, stream: true, max_tokens: 512,
        messages: [{ role: "user", content: "Count from 1 to 200, writing each number on its own line." }] }),
    })
    if (!response.ok) throw new Error(`Cancellation probe HTTP ${response.status}`)
    const reader = response.body!.getReader()
    const decoder = new TextDecoder()
    let buffer = ""
    try {
      while (true) {
        const chunk = await reader.read()
        if (chunk.done) break
        buffer += decoder.decode(chunk.value, { stream: true })
        const lines = buffer.split("\n")
        buffer = lines.pop() ?? ""
        for (const line of lines) {
          if (!line.startsWith("data: ") || line.includes("[DONE]")) continue
          const event = JSON.parse(line.slice(6))
          const choice = event.choices?.[0]
          const delta = choice?.delta
          if (delta?.content || delta?.reasoning_content || delta?.reasoning) receivedData = true
          if (choice?.finish_reason) streamFinishedBeforeAbort = true
        }
        if (receivedData) break
      }
      cancel.abort()
      await reader.cancel().catch(() => {})
    } finally { reader.releaseLock() }
  } finally { clearTimeout(timeout); cancel.abort() }
  const recoveryStart = Date.now()
  const followup = await chains[0].call([
    { role: "system", content: "Reply with only OK." },
    { role: "user", content: "Confirm." },
  ])
  console.log(JSON.stringify({ phase: "disconnect-recovery", receivedData, streamFinishedBeforeAbort,
    followupSucceeded: !!followup.trim(), followupMs: Date.now() - recoveryStart,
    caveat: "An accepted follow-up is evidence of recovery, not proof of GPU cancellation.",
    queues: providerQueueStats().map(({ active, waiting }) => ({ active, waiting })),
  }))
} finally { for (const chain of chains) chain.dispose() }
