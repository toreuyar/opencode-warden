import type { LlmMessage } from "../types.js"
import type { LlmChatLogger } from "../audit/llm-chat-logger.js"
import { checkRequest, LlmInferenceTimeoutError } from "./request-context.js"

/**
 * Error thrown by LLM API calls that includes the HTTP status code.
 * Allows ProviderChain to distinguish exhaustion (429/402/503) from other errors.
 */
export class LlmApiError extends Error {
  constructor(public statusCode: number, message: string, public retryAfterMs?: number) {
    super(message)
    this.name = "LlmApiError"
  }
}

export function parseRetryAfter(value: string | null, now = Date.now()): number | undefined {
  if (!value) return undefined
  if (/^\d+(?:\.\d+)?$/.test(value.trim())) {
    const ms = Number(value) * 1000
    return Number.isFinite(ms) ? Math.min(ms, 2147483647) : undefined
  }
  const date = Date.parse(value)
  return Number.isFinite(date) ? Math.min(2147483647, Math.max(0, date - now)) : undefined
}

function requestAbort(timeout: number, signal?: AbortSignal) {
  checkRequest(signal)
  const controller = new AbortController()
  const abort = () => controller.abort(signal?.reason)
  signal?.addEventListener("abort", abort, { once: true })
  const timer = setTimeout(() => controller.abort(new LlmInferenceTimeoutError()), timeout)
  return {
    controller,
    dispose: () => {
      clearTimeout(timer)
      signal?.removeEventListener("abort", abort)
    },
  }
}

/**
 * Build merged HTTP headers for LLM requests.
 * Merge order: Content-Type → Bearer auth from apiKey → custom headers (overrides).
 */
export function buildLlmHeaders(
  apiKey: string,
  customHeaders: Record<string, string>,
): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  }
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`
  }
  // Custom headers override auto-generated ones
  for (const [key, value] of Object.entries(customHeaders)) {
    headers[key] = value
  }
  return headers
}

export interface CallLlmOptions {
  signal?: AbortSignal
  requestID?: string
  attemptID?: string
  baseUrl: string
  completionsPath: string
  model: string
  messages: LlmMessage[]
  temperature: number
  /** Generation cap (sent as max_tokens). finish_reason "length" → thrown
   * error → provider chain fails closed: a command whose evaluation cannot
   * conclude within the cap is itself the risk signal. */
  maxTokens?: number
  timeout: number
  headers: Record<string, string>
  debugLog?: (msg: string) => void
  chatLogger?: LlmChatLogger
  componentName?: string
}

/**
 * Shared POST to the chat completions endpoint.
 * Returns the content string from `choices[0].message.content`.
 *
 * When `chatLogger` is provided, uses SSE streaming (`stream: true`) and
 * writes tokens to the chat log in real-time. Otherwise behaves exactly
 * as the non-streaming path.
 */
export async function callLlm(options: CallLlmOptions): Promise<string> {
  if (options.chatLogger) {
    return callLlmStreaming(options)
  }
  return callLlmNonStreaming(options)
}

/**
 * Original non-streaming path — unchanged behavior.
 */
async function callLlmNonStreaming(options: CallLlmOptions): Promise<string> {
  const url = `${options.baseUrl}${options.completionsPath}`
  const log = options.debugLog

  const requestBody: Record<string, unknown> = {
    model: options.model,
    messages: options.messages,
    temperature: options.temperature,
  }
  if (options.maxTokens && options.maxTokens > 0) {
    requestBody.max_tokens = options.maxTokens
  }

  log?.(`POST ${url} model=${options.model}`)
  log?.(`REQUEST BODY:\n${JSON.stringify(requestBody, null, 2)}`)

  const { controller, dispose } = requestAbort(options.timeout, options.signal)
  const start = Date.now()

  try {
    const req = new Request(url, {
      method: "POST",
      headers: options.headers,
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    })
    // Disable Bun's built-in fetch timeout — we manage our own via AbortController
    ;(req as any).timeout = false
    const resp = await fetch(req)

    const elapsed = Date.now() - start
    log?.(`POST ${url} → ${resp.status} (${elapsed}ms)`)

    if (!resp.ok) {
      const errorBody = await resp.text().catch(() => "(unreadable)")
      log?.(`ERROR RESPONSE:\n${errorBody}`)
      throw new LlmApiError(resp.status, `LLM API error: ${resp.status} ${resp.statusText}`, parseRetryAfter(resp.headers.get("retry-after")))
    }

    const data = (await resp.json()) as {
      choices: Array<{ message: { content: string }; finish_reason?: string }>
    }

    log?.(`RESPONSE BODY:\n${JSON.stringify(data, null, 2)}`)

    // Generation-cap hit → treat as evaluation failure (fail-closed upstream)
    if (data.choices?.[0]?.finish_reason === "length") {
      log?.(`POST ${url} → GENERATION CAP HIT (finish_reason=length, max_tokens=${options.maxTokens})`)
      throw new Error(
        `LLM generation cap exceeded (max_tokens=${options.maxTokens}) — evaluation inconclusive, failing closed`,
      )
    }

    return data.choices?.[0]?.message?.content || ""
  } catch (err) {
    const elapsed = Date.now() - start
    const errMsg = err instanceof Error ? err.message : String(err)

    // Re-throw LlmApiError as-is (already classified)
    if (err instanceof LlmApiError) throw err
    checkRequest(options.signal)

    // Classify the error for better diagnostics
    if (controller.signal.aborted) {
      log?.(`POST ${url} → ABORTED by timeout after ${elapsed}ms (configured: ${options.timeout}ms)`)
      throw new LlmInferenceTimeoutError()
    }
    if (errMsg.includes("timed out") || errMsg.includes("timeout")) {
      log?.(`POST ${url} → TIMED OUT after ${elapsed}ms (external timeout, not our AbortController — configured: ${options.timeout}ms)`)
      throw new LlmInferenceTimeoutError()
    }

    log?.(`POST ${url} → ERROR after ${elapsed}ms: ${errMsg}`)
    throw err
  } finally {
    dispose()
  }
}

/**
 * Streaming path — uses `stream: true` and SSE parsing.
 * Writes tokens to the chat log in real-time via chatLogger.
 * Returns the assembled full response string.
 */
async function callLlmStreaming(options: CallLlmOptions): Promise<string> {
  const url = `${options.baseUrl}${options.completionsPath}`
  const log = options.debugLog
  const chatLogger = options.chatLogger!.fork(options.requestID ?? crypto.randomUUID(), options.attemptID ?? crypto.randomUUID())
  const componentName = options.componentName || "unknown"

  const requestBody: Record<string, unknown> = {
    model: options.model,
    messages: options.messages,
    temperature: options.temperature,
    stream: true,
  }
  if (options.maxTokens && options.maxTokens > 0) {
    requestBody.max_tokens = options.maxTokens
  }

  log?.(`POST ${url} model=${options.model} stream=true`)
  // Don't log REQUEST BODY / RESPONSE BODY — the chat log has a better version

  const { controller, dispose } = requestAbort(options.timeout, options.signal)
  const start = Date.now()

  // Determine tool name from messages (last user message often contains the tool)
  const lastUserMsg = options.messages.findLast((m) => m.role === "user")
  const toolHint = lastUserMsg?.content.match(/Tool:\s*(\S+)/i)?.[1] || "-"

  chatLogger.startCall(componentName, toolHint, options.messages)

  try {
    const req = new Request(url, {
      method: "POST",
      headers: options.headers,
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    })
    ;(req as any).timeout = false
    const resp = await fetch(req)

    const elapsed = Date.now() - start
    log?.(`POST ${url} → ${resp.status} (${elapsed}ms)`)

    if (!resp.ok) {
      const errorBody = await resp.text().catch(() => "(unreadable)")
      log?.(`ERROR RESPONSE:\n${errorBody}`)
      chatLogger.endCall(Date.now() - start)
      throw new LlmApiError(resp.status, `LLM API error: ${resp.status} ${resp.statusText}`, parseRetryAfter(resp.headers.get("retry-after")))
    }

    // Check content type — if server doesn't support streaming, fall back
    const contentType = resp.headers.get("content-type") || ""
    if (contentType.includes("application/json")) {
      // Server returned non-streaming JSON despite stream:true request
      const data = (await resp.json()) as {
        choices: Array<{ message: { content: string }; finish_reason?: string }>
      }
      if (data.choices?.[0]?.finish_reason === "length") {
        chatLogger.endCall(Date.now() - start)
        throw new Error(
          `LLM generation cap exceeded (max_tokens=${options.maxTokens}) — evaluation inconclusive, failing closed`,
        )
      }
      const content = data.choices?.[0]?.message?.content || ""
      chatLogger.writeChunk(content)
      chatLogger.endCall(Date.now() - start)
      return content
    }

    // SSE streaming response
    const content = await readSseStream(resp, chatLogger)
    chatLogger.endCall(Date.now() - start)
    log?.(`Streaming complete: ${content.length} chars (${Date.now() - start}ms)`)
    return content
  } catch (err) {
    const elapsed = Date.now() - start
    const errMsg = err instanceof Error ? err.message : String(err)

    chatLogger.endCall(elapsed)

    // Re-throw LlmApiError as-is (already classified)
    if (err instanceof LlmApiError) throw err
    checkRequest(options.signal)

    if (controller.signal.aborted) {
      log?.(`POST ${url} → ABORTED by timeout after ${elapsed}ms (configured: ${options.timeout}ms)`)
      throw new LlmInferenceTimeoutError()
    }
    if (errMsg.includes("timed out") || errMsg.includes("timeout")) {
      log?.(`POST ${url} → TIMED OUT after ${elapsed}ms (external timeout, not our AbortController — configured: ${options.timeout}ms)`)
      throw new LlmInferenceTimeoutError()
    }

    log?.(`POST ${url} → ERROR after ${elapsed}ms: ${errMsg}`)
    throw err
  } finally {
    dispose()
  }
}

/**
 * Read an SSE stream from the response body, writing tokens to the chat logger.
 * Returns the assembled content string.
 */
async function readSseStream(
  resp: Response,
  chatLogger: LlmChatLogger,
): Promise<string> {
  const body = resp.body
  if (!body) return ""

  const reader = body.getReader()
  const decoder = new TextDecoder()
  let buffer = ""
  let content = ""
  let finishReason: string | undefined

  const processSseLine = (line: string) => {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith(":")) return
    if (trimmed === "data: [DONE]") return

    if (trimmed.startsWith("data: ")) {
      const jsonStr = trimmed.slice(6)
      try {
        const event = JSON.parse(jsonStr) as {
          choices?: Array<{
            delta?: {
              content?: string
              reasoning_content?: string
              reasoning?: string
            }
            finish_reason?: string | null
          }>
        }

        if (event.choices?.[0]?.finish_reason) {
          finishReason = event.choices[0].finish_reason || undefined
        }

        const delta = event.choices?.[0]?.delta
        if (!delta) return

        // Thinking/reasoning tokens (DeepSeek uses reasoning_content, Ollama uses reasoning)
        const thinking = delta.reasoning_content || delta.reasoning
        if (thinking) {
          chatLogger.writeThinkingChunk(thinking)
        }

        // Content tokens
        if (delta.content) {
          chatLogger.writeChunk(delta.content)
          content += delta.content
        }
      } catch {
        // Malformed JSON in SSE event — skip
      }
    }
  }

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })

      // Process complete SSE lines
      const lines = buffer.split("\n")
      // Keep the last (potentially incomplete) line in the buffer
      buffer = lines.pop() || ""

      for (const line of lines) {
        processSseLine(line)
      }
    }

    // Process any remaining data in the buffer after stream ends
    if (buffer.trim()) {
      processSseLine(buffer)
    }
  } finally {
    reader.releaseLock()
  }

  // Generation-cap hit → evaluation failure (fail-closed upstream)
  if (finishReason === "length") {
    throw new Error(
      "LLM generation cap exceeded (finish_reason=length) — evaluation inconclusive, failing closed",
    )
  }

  return content
}

export interface CheckLlmHealthOptions {
  signal?: AbortSignal
  baseUrl: string
  healthCheckPath: string
  timeout: number
  headers: Record<string, string>
  debugLog?: (msg: string) => void
}

/**
 * Shared GET to the health check endpoint.
 * Returns true if the endpoint responds with an OK status.
 */
export async function checkLlmHealth(
  options: CheckLlmHealthOptions,
): Promise<boolean> {
  const url = `${options.baseUrl}${options.healthCheckPath}`
  const log = options.debugLog

  const { controller, dispose } = requestAbort(options.timeout, options.signal)
  const start = Date.now()

  try {
    const req = new Request(url, {
      headers: options.headers,
      signal: controller.signal,
    })
    // Disable Bun's built-in fetch timeout — we manage our own via AbortController
    ;(req as any).timeout = false
    const resp = await fetch(req)

    log?.(
      `Health check GET ${url} → ${resp.status} ${resp.ok ? "OK" : "FAIL"} (${Date.now() - start}ms)`,
    )

    return resp.ok
  } catch (err) {
    log?.(
      `Health check GET ${url} → FAILED (${Date.now() - start}ms): ${err instanceof Error ? err.message : err}`,
    )
    return false
  } finally {
    dispose()
  }
}
