import type { LlmMessage, LlmProviderConfig } from "../types.js"
import type { LlmChatLogger } from "../audit/llm-chat-logger.js"
import { buildLlmHeaders, callLlm, checkLlmHealth, LlmApiError } from "./client.js"

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
    baseUrl: raw.baseUrl || "",
    model: raw.model || "",
    apiKey: raw.apiKey || "",
    timeout: raw.timeout || 0,
    temperature: raw.temperature ?? 0,
    headers: raw.headers || {},
    healthCheckPath: raw.healthCheckPath || "",
    completionsPath: raw.completionsPath || "",
  }
}

export interface ProviderCallOptions {
  temperature?: number
  componentName?: string
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

  // Runtime cooldown tracking: providerIndex → timestamp when exhausted
  private readonly exhaustedAt = new Map<number, number>()

  constructor(
    providers: LlmProviderConfig[],
    debugLog?: (msg: string) => void,
    chatLogger?: LlmChatLogger,
  ) {
    // Normalize all providers to ensure complete fields with safe defaults
    this.providers = providers.map((p, i) => normalizeProvider(p, i))
    this.debugLog = debugLog
    this.chatLogger = chatLogger
  }

  /**
   * Execute an LLM call with automatic fallback through the provider chain.
   */
  async call(messages: LlmMessage[], options: ProviderCallOptions = {}): Promise<string> {
    const errors: string[] = []

    for (let i = 0; i < this.providers.length; i++) {
      const provider = this.providers[i]
      const name = provider.name

      // Check cooldown
      if (this.isOnCooldown(i)) {
        const remaining = this.cooldownRemaining(i)
        this.debugLog?.(`ProviderChain: skipping ${name} (on cooldown, ${remaining}ms remaining)`)
        errors.push(`${name}: on cooldown`)
        continue
      }

      try {
        this.debugLog?.(`ProviderChain: trying ${name} (${provider.baseUrl} model=${provider.model})`)

        const headers = buildLlmHeaders(provider.apiKey, provider.headers)
        const response = await callLlm({
          baseUrl: provider.baseUrl,
          completionsPath: provider.completionsPath,
          model: provider.model,
          messages,
          temperature: options.temperature ?? provider.temperature,
          timeout: provider.timeout,
          headers,
          debugLog: this.debugLog,
          chatLogger: this.chatLogger,
          componentName: options.componentName,
        })

        // Success — reset cooldown for this provider
        this.exhaustedAt.delete(i)

        if (i > 0) {
          this.debugLog?.(`ProviderChain: ${name} succeeded (fallback from provider #1)`)
        }

        return response
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err)

        if (err instanceof LlmApiError && isExhausted(err.statusCode)) {
          // Exhaustion — mark with cooldown timestamp
          if (provider.cooldown > 0) {
            this.exhaustedAt.set(i, Date.now())
            this.debugLog?.(`ProviderChain: ${name} exhausted (HTTP ${err.statusCode}) — cooldown ${provider.cooldown}ms`)
          } else {
            this.debugLog?.(`ProviderChain: ${name} exhausted (HTTP ${err.statusCode}) — no cooldown, will retry next call`)
          }
          errors.push(`${name}: exhausted (${err.statusCode})`)
        } else {
          // Transient error — no cooldown, try next
          this.debugLog?.(`ProviderChain: ${name} failed: ${errMsg}`)
          errors.push(`${name}: ${errMsg}`)
        }
      }
    }

    // All providers exhausted or failed
    throw new Error(`All LLM providers failed: ${errors.join("; ")}`)
  }

  /**
   * Health check — returns true if at least one provider responds.
   */
  async healthCheck(): Promise<boolean> {
    for (const provider of this.providers) {
      try {
        const headers = buildLlmHeaders(provider.apiKey, provider.headers)
        const healthy = await checkLlmHealth({
          baseUrl: provider.baseUrl,
          healthCheckPath: provider.healthCheckPath,
          timeout: 5000,
          headers,
          debugLog: this.debugLog,
        })
        if (healthy) return true
      } catch {
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
