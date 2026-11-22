import type { LlmMessage, LlmProviderConfig, LlmRequestPolicy } from "../types.js"
import type { LlmChatLogger } from "../audit/llm-chat-logger.js"
import { buildLlmHeaders, callLlm, checkLlmHealth, LlmApiError } from "./client.js"
import { DEFAULT_REQUEST_POLICY, ProviderOverloadError, registerProviderQueues, retryDelay } from "./request-queue.js"
import { checkRequest, currentLlmRequest, LlmInferenceTimeoutError, LlmRequestError, waitForRetry, withLlmRequest } from "./request-context.js"

const EXHAUSTION_CODES = [429, 402, 503]

function isExhausted(statusCode: number): boolean {
  return EXHAUSTION_CODES.includes(statusCode)
}

/**
 * Normalize a potentially incomplete provider config with safe defaults.
 * Protects against:
 * - Flat-field normalization producing incomplete objects
 * - User-supplied providers arrays with missing fields
 * - Any edge case in config resolution
 */
function normalizeProvider(raw: Partial<LlmProviderConfig>, index: number): LlmProviderConfig {
  return {
    name: raw.name || `provider-${index + 1}`,
    cooldown: raw.cooldown ?? 0,
    requestPolicy: raw.requestPolicy,
    baseUrl: raw.baseUrl || "",
    model: raw.model || "",
    apiKey: raw.apiKey || "",
    timeout: raw.timeout || 0,
    temperature: raw.temperature ?? 0,
    maxTokens: raw.maxTokens,
    headers: raw.headers || {},
    healthCheckPath: raw.healthCheckPath || "",
    completionsPath: raw.completionsPath || "",
  }
}

export interface ProviderCallOptions {
  signal?: AbortSignal
  temperature?: number
  componentName?: string
  retryCount?: number
  /** Validate raw text inside the attempt loop before accepting a response. */
  validateResponse?: (response: string) => string
}

/**
 * Ordered fallback chain of LLM providers.
 *
 * On each `call()`, iterates providers in order:
 * 1. Skip providers on cooldown (unless cooldown=0)
 * 2. Try callLlm() with the provider's endpoint config
 * 3. On success: return response, reset cooldown for that provider
 * 4. On exhaustion (429/402/503): mark provider with cooldown timestamp, try next
 * 5. On other error: try next provider (no cooldown — transient failure)
 * 6. If all providers exhausted/failed: throw (fail-closed)
 */
export class ProviderChain {
  private readonly providers: LlmProviderConfig[]
  private readonly debugLog?: (msg: string) => void
  private readonly chatLogger?: LlmChatLogger
  private readonly registration: ReturnType<typeof registerProviderQueues>
  private readonly lifetime = new AbortController()

  // Runtime cooldown tracking: providerIndex → timestamp when exhausted
  private readonly exhaustedAt = new Map<number, number>()

  constructor(
    providers: LlmProviderConfig[],
    debugLog?: (msg: string) => void,
    chatLogger?: LlmChatLogger,
    owner?: string,
  ) {
    // Normalize all providers to ensure complete fields with safe defaults
    this.providers = providers.map((p, i) => normalizeProvider(p, i))
    this.registration = registerProviderQueues(this.providers, owner)
    this.debugLog = debugLog
    this.chatLogger = chatLogger
  }

  getTotalTimeout(): number {
    return this.providers.length
      ? Math.min(...this.providers.map((provider) => provider.requestPolicy?.totalTimeoutMs ?? DEFAULT_REQUEST_POLICY.totalTimeoutMs))
      : DEFAULT_REQUEST_POLICY.totalTimeoutMs
  }

  updateRequestPolicy(index: number, policy: LlmRequestPolicy): void {
    checkRequest(this.lifetime.signal)
    if (!this.providers[index]) throw new Error("Warden: Unknown provider index")
    this.registration.update(index, policy)
    this.providers[index].requestPolicy = { ...policy }
  }

  dispose(): void {
    this.lifetime.abort(new LlmRequestError("cancelled"))
    this.registration.dispose()
  }

  /**
   * Execute an LLM call with automatic fallback through the provider chain.
   */
  async call(messages: LlmMessage[], options: ProviderCallOptions = {}): Promise<string> {
    return this.callValidated(messages, options.validateResponse ?? ((response) => response), options)
  }

  /**
   * Execute an LLM call and validate the response before accepting it. Validator
   * failures retry the same provider up to retryCount, then fall back to the next
   * provider. If all providers fail validation or transport, the call fails closed.
   */
  async callValidated<T>(
    messages: LlmMessage[],
    validate: (response: string) => T,
    options: ProviderCallOptions = {},
  ): Promise<T> {
    return withLlmRequest({
      signal: options.signal ? AbortSignal.any([options.signal, this.lifetime.signal]) : this.lifetime.signal,
      timeoutMs: this.getTotalTimeout(),
    },
      () => this.runValidated(messages, validate, options))
  }

  private async runValidated<T>(
    messages: LlmMessage[],
    validate: (response: string) => T,
    options: ProviderCallOptions,
  ): Promise<T> {
    const scope = currentLlmRequest()!
    const callID = crypto.randomUUID()
    const errors: string[] = []
    const retryCount = Math.max(0, options.retryCount ?? 0)
    let overload: ProviderOverloadError | undefined
    // Snapshot once: queued/retried calls must never observe later context mutations.
    messages = messages.map((message) => ({ ...message }))

    for (let i = 0; i < this.providers.length; i++) {
      checkRequest(scope.signal)
      const provider = this.providers[i]
      const queue = this.registration.queues[i]
      const name = provider.name
      const policy = { ...DEFAULT_REQUEST_POLICY, ...provider.requestPolicy }
      const attempts = provider.requestPolicy?.maxAttempts ?? (retryCount + 1)

      // Check cooldown
      if (this.isOnCooldown(i)) {
        const remaining = this.cooldownRemaining(i)
        this.debugLog?.(`ProviderChain: skipping ${name} (on cooldown, ${remaining}ms remaining)`)
        errors.push(`${name}: on cooldown`)
        continue
      }

      for (let attempt = 0; attempt < attempts; attempt++) {
        try {
          checkRequest(scope.signal)
          const attemptID = crypto.randomUUID()
          this.debugLog?.(`LLM scheduling ${JSON.stringify({ requestID: scope.id, callID, attemptID, attempt: attempt + 1, phase: "admission", ...queue.snapshot() })}`)
          this.debugLog?.(`ProviderChain: trying ${name} (${provider.baseUrl} model=${provider.model}) attempt=${attempt + 1}/${attempts}`)

          const headers = buildLlmHeaders(provider.apiKey, provider.headers)
          const release = await queue.acquire(policy.queueTimeoutMs, scope.signal)
          let response: string
          let transportStarted = false
          try {
            checkRequest(scope.signal)
            this.debugLog?.(`LLM scheduling ${JSON.stringify({ requestID: scope.id, callID, attemptID, attempt: attempt + 1, phase: "inference", ...queue.snapshot() })}`)
            transportStarted = true
            response = await callLlm({
              signal: scope.signal,
              requestID: scope.id,
              attemptID,
              baseUrl: provider.baseUrl,
              completionsPath: provider.completionsPath,
              model: provider.model,
              messages,
              temperature: options.temperature ?? provider.temperature,
              maxTokens: provider.maxTokens,
              timeout: Math.max(1, Math.min(provider.timeout, scope.deadline - Date.now())),
              headers,
              debugLog: this.debugLog,
              chatLogger: this.chatLogger,
              componentName: options.componentName,
            })
          } catch (error) {
            if (transportStarted && (error instanceof LlmInferenceTimeoutError || scope.signal.aborted)) {
              queue.pause(policy.recoveryDelayMs)
            } else if (error instanceof LlmApiError && (error.statusCode === 429 || error.statusCode >= 500)) {
              queue.pause(error.retryAfterMs ?? 0)
            }
            throw error
          } finally {
            release()
          }
          checkRequest(scope.signal)
          if (!response.trim()) throw new Error("LLM returned an empty response")

          const validated = validate(response)

          // Success — reset cooldown for this provider
          this.exhaustedAt.delete(i)

          if (i > 0) {
            this.debugLog?.(`ProviderChain: ${name} succeeded (fallback from provider #1)`)
          }

          return validated
        } catch (err) {
          checkRequest(scope.signal)
          if (err instanceof LlmRequestError) throw err
          const errMsg = err instanceof Error ? err.message : String(err)
          if (err instanceof ProviderOverloadError) {
            overload = err
            errors.push(err.message)
            break // Local overload is bounded by queue policy, not retried.
          }

          // Explicit request policy retries transport, empty-response and validator
          // failures before fallback, including overload responses from the server.
          const permanent = err instanceof LlmApiError &&
            [400, 401, 402, 403, 404, 405, 413, 422].includes(err.statusCode)
          if (provider.requestPolicy?.maxAttempts !== undefined && attempt + 1 < attempts && !permanent) {
            const delay = Math.max(
              retryDelay(attempt, policy.initialDelayMs, policy.maxDelayMs),
              err instanceof LlmApiError ? err.retryAfterMs ?? 0 : 0,
            )
            this.debugLog?.(`ProviderChain: retrying ${name} in ${delay}ms`)
            queue.retry(callID, attempt + 2, delay)
            this.debugLog?.(`LLM scheduling ${JSON.stringify({ requestID: scope.id, callID, phase: "backoff", attempt: attempt + 2, delayMs: delay, ...queue.snapshot() })}`)
            try { await waitForRetry(delay, scope.signal) } finally { queue.clearRetry(callID) }
            continue
          }

          if (err instanceof LlmApiError && isExhausted(err.statusCode)) {
            // Exhaustion — mark with cooldown timestamp
            if (provider.cooldown > 0) {
              this.exhaustedAt.set(i, Date.now())
              this.debugLog?.(`ProviderChain: ${name} exhausted (HTTP ${err.statusCode}) — cooldown ${provider.cooldown}ms`)
            } else {
              this.debugLog?.(`ProviderChain: ${name} exhausted (HTTP ${err.statusCode}) — no cooldown, will retry next call`)
            }
            errors.push(`${name}: exhausted (${err.statusCode})`)
            break
          }

          if (provider.requestPolicy?.maxAttempts === undefined && attempt < retryCount) {
            this.debugLog?.(`ProviderChain: ${name} attempt ${attempt + 1} failed, retrying: ${errMsg}`)
            continue
          }

          // Transient or validator error — no cooldown, try next provider
          this.debugLog?.(`ProviderChain: ${name} failed: ${errMsg}`)
          errors.push(`${name}: ${errMsg}`)
        }
        break
      }
    }

    // All providers exhausted or failed
    if (overload) throw overload
    throw new Error(`All LLM providers failed: ${errors.join("; ")}`)
  }

  /**
   * Health check — returns true if at least one provider responds.
   */
  async healthCheck(): Promise<boolean> {
    try {
      return await withLlmRequest({ signal: this.lifetime.signal, timeoutMs: this.getTotalTimeout() }, () => this.checkHealth())
    } catch { return false }
  }

  private async checkHealth(): Promise<boolean> {
    const scope = currentLlmRequest()!
    for (const [i, provider] of this.providers.entries()) {
      try {
        const headers = buildLlmHeaders(provider.apiKey, provider.headers)
        const release = await this.registration.queues[i].acquire(
          provider.requestPolicy?.queueTimeoutMs ?? DEFAULT_REQUEST_POLICY.queueTimeoutMs,
          scope.signal,
        )
        let healthy: boolean
        try {
          healthy = await checkLlmHealth({
            signal: scope.signal,
            baseUrl: provider.baseUrl,
            healthCheckPath: provider.healthCheckPath,
            timeout: 5000,
            headers,
            debugLog: this.debugLog,
          })
        } finally {
          release()
        }
        if (healthy) return true
      } catch {
        checkRequest(scope.signal)
        // Try next provider
      }
    }
    return false
  }

  /**
   * Returns true if at least one provider is not on cooldown.
   * An empty providers array means nothing is available.
   */
  isAvailable(): boolean {
    if (this.providers.length === 0) return false

    for (let i = 0; i < this.providers.length; i++) {
      if (!this.isOnCooldown(i)) return true
    }
    return false
  }

  /**
   * Get provider info for display purposes (dashboard, logging).
   */
  getProviderInfo(): Array<{ name: string; onCooldown: boolean; cooldownRemaining: number }> {
    return this.providers.map((p, i) => ({
      name: p.name,
      onCooldown: this.isOnCooldown(i),
      cooldownRemaining: this.cooldownRemaining(i),
    }))
  }

  private isOnCooldown(index: number): boolean {
    const provider = this.providers[index]
    if (!provider || provider.cooldown <= 0) return false

    const exhaustedTime = this.exhaustedAt.get(index)
    if (exhaustedTime === undefined) return false

    return Date.now() - exhaustedTime < provider.cooldown
  }

  private cooldownRemaining(index: number): number {
    const provider = this.providers[index]
    if (!provider || provider.cooldown <= 0) return 0

    const exhaustedTime = this.exhaustedAt.get(index)
    if (exhaustedTime === undefined) return 0

    const remaining = provider.cooldown - (Date.now() - exhaustedTime)
    return Math.max(0, remaining)
  }
}
