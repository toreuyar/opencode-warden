import type { LlmProviderConfig, LlmRequestPolicy, ProviderQueueStats } from "../types.js"
import { DEFAULT_REQUEST_POLICY } from "../config/defaults.js"
import { checkRequest } from "./request-context.js"
export { DEFAULT_REQUEST_POLICY } from "../config/defaults.js"

export const PROVIDER_OVERLOAD_MESSAGE =
  "Warden: LLM provider overloaded by concurrent requests (queue full or wait timed out). Operation blocked; retry later."
const overloadBrand = Symbol.for("opencode-warden.provider-overload.v1")
export class ProviderOverloadError extends Error {
  readonly [overloadBrand] = true
  static [Symbol.hasInstance](value: unknown): boolean {
    return value instanceof Error && (value as unknown as Record<symbol, unknown>)[overloadBrand] === true
  }
  constructor(timeout = false) {
    super(timeout
      ? "Warden: LLM provider overloaded by concurrent requests — queue wait timed out. Retry later."
      : "Warden: LLM provider overloaded by concurrent requests — request queue is full. Retry later.")
  }
}

class RequestQueue {
  readonly id = crypto.randomUUID()
  private active = 0
  private limit = Infinity
  private pendingLimit = Infinity
  private recoveryUntil = 0
  private wake?: ReturnType<typeof setTimeout>
  private queueFullCount = 0
  private queueTimeoutCount = 0
  private cancelledCount = 0
  private definitions = new Map<string, { token: symbol; policy?: LlmRequestPolicy }>()
  private retries = new Map<string, { attempt: number; next: number }>()
  private pending: Array<{ since: number; start: () => void }> = []

  register(owner: string, token: symbol, policy?: LlmRequestPolicy): void {
    this.definitions.set(owner, { token, policy })
    this.recalculate()
  }

  unregister(owner: string, token: symbol): void {
    if (this.definitions.get(owner)?.token !== token) return
    this.definitions.delete(owner)
    this.recalculate()
  }

  update(owner: string, token: symbol, policy?: LlmRequestPolicy): void {
    if (this.definitions.get(owner)?.token !== token) {
      throw new Error("Warden: Provider registration has been replaced")
    }
    this.register(owner, token, policy)
  }

  private recalculate(): void {
    this.limit = Infinity
    this.pendingLimit = Infinity
    for (const { policy } of this.definitions.values()) {
      const resolved = { ...DEFAULT_REQUEST_POLICY, ...policy }
      if (resolved.concurrency > 0) {
        this.limit = Math.min(this.limit, resolved.concurrency)
        this.pendingLimit = Math.min(this.pendingLimit, resolved.maxQueueSize)
      }
    }
    // Existing waiters retain admission; a smaller queue cap applies to new arrivals.
    this.drain()
  }

  pause(ms: number): void {
    if (ms <= 0) return
    this.recoveryUntil = Math.max(this.recoveryUntil, Date.now() + ms)
    this.drain()
  }

  retry(requestID: string, attempt: number, delay: number): void {
    this.retries.set(requestID, { attempt, next: Date.now() + delay })
  }

  clearRetry(requestID: string): void { this.retries.delete(requestID) }

  visible(): boolean { return this.definitions.size > 0 || this.active > 0 || this.pending.length > 0 || this.retries.size > 0 }

  snapshot(): ProviderQueueStats {
    const now = Date.now()
    return {
      id: this.id, active: this.active, concurrency: Number.isFinite(this.limit) ? this.limit : null,
      waiting: this.pending.length, maxQueueSize: Number.isFinite(this.pendingLimit) ? this.pendingLimit : null,
      oldestWaitMs: this.pending.length ? now - this.pending[0].since : 0,
      recoveryRemainingMs: Math.max(0, this.recoveryUntil - now),
      queueFullCount: this.queueFullCount, queueTimeoutCount: this.queueTimeoutCount,
      cancelledCount: this.cancelledCount,
      retries: [...this.retries].map(([requestID, retry]) => ({
        requestID, attempt: retry.attempt, delayRemainingMs: Math.max(0, retry.next - now),
      })),
    }
  }

  async acquire(timeout: number, signal?: AbortSignal): Promise<() => void> {
    checkRequest(signal)
    if (!this.pending.length && this.active < this.limit && Date.now() >= this.recoveryUntil) {
      this.active++
      return this.releaseOnce()
    }
    if (this.pending.length >= this.pendingLimit) {
      this.queueFullCount++
      throw new ProviderOverloadError()
    }
    return new Promise((resolve, reject) => {
      const since = Date.now()
      const deadline = since + timeout
      const cleanup = () => {
        clearTimeout(timer)
        signal?.removeEventListener("abort", abort)
      }
      const remove = () => {
        const index = this.pending.indexOf(entry)
        if (index >= 0) this.pending.splice(index, 1)
        cleanup()
      }
      const abort = () => {
        remove()
        this.cancelledCount++
        try { checkRequest(signal) } catch (error) { reject(error) }
        this.drain()
      }
      const entry = {
        since,
        start: () => {
          cleanup()
          if (signal?.aborted) {
            this.cancelledCount++
            try { checkRequest(signal) } catch (error) { reject(error) }
          } else if (Date.now() >= deadline) {
            this.queueTimeoutCount++
            reject(new ProviderOverloadError(true))
          } else {
            this.active++
            resolve(this.releaseOnce())
          }
        },
      }
      const timer = setTimeout(() => {
        remove()
        this.queueTimeoutCount++
        reject(new ProviderOverloadError(true))
        this.drain()
      }, timeout)
      this.pending.push(entry)
      signal?.addEventListener("abort", abort, { once: true })
      if (signal?.aborted) abort()
      else this.drain()
    })
  }

  private drain(): void {
    clearTimeout(this.wake)
    this.wake = undefined
    const delay = this.recoveryUntil - Date.now()
    if (delay > 0) {
      if (this.pending.length) this.wake = setTimeout(() => this.drain(), Math.min(delay, 2147483647))
      return
    }
    while (this.active < this.limit && this.pending.length) this.pending.shift()!.start()
  }

  private releaseOnce(): () => void {
    let released = false
    return () => {
      if (released) return
      released = true
      this.active--
      this.drain()
    }
  }
}

const registryKey = Symbol.for("opencode-warden.provider-queues.v2")
const scope = globalThis as typeof globalThis & { [registryKey]?: Map<string, RequestQueue> }
const queues = scope[registryKey] ??= new Map<string, RequestQueue>()
function queueKey(provider: LlmProviderConfig): string {
  const endpoint = `${provider.baseUrl.replace(/\/+$/, "")}/${provider.completionsPath.replace(/^\/+/, "")}`
  let key = endpoint
  try { key = new URL(endpoint).href } catch { /* transport rejects invalid endpoints */ }
  return key
}

export function providerQueueID(provider: LlmProviderConfig): string | undefined {
  return queues.get(queueKey(provider))?.id
}

function lookup(provider: LlmProviderConfig): RequestQueue {
  const key = queueKey(provider)
  let queue = queues.get(key)
  if (!queue) { queue = new RequestQueue(); queues.set(key, queue) }
  return queue
}

/** Stable owner + per-registration token makes reloads replace old limits.
 * Disposing an old chain cannot delete the new chain's registration.
 */
export function registerProviderQueues(providers: LlmProviderConfig[], owner: string = crypto.randomUUID()) {
  const token = Symbol()
  const entries = providers.map((provider, i) => ({ queue: lookup(provider), owner: `${owner}:${i}` }))
  for (const [i, entry] of entries.entries()) entry.queue.register(entry.owner, token, providers[i].requestPolicy)
  return {
    queues: entries.map((entry) => entry.queue),
    update(index: number, policy?: LlmRequestPolicy) {
      const entry = entries[index]
      if (!entry) throw new Error("Warden: Unknown provider index")
      entry.queue.update(entry.owner, token, policy)
    },
    dispose() { for (const entry of entries) entry.queue.unregister(entry.owner, token) },
  }
}

// Standalone callers keep one registration per provider object.
const standalone = new WeakMap<LlmProviderConfig, ReturnType<typeof registerProviderQueues>>()
export function providerQueue(provider: LlmProviderConfig): RequestQueue {
  let registration = standalone.get(provider)
  if (!registration) {
    registration = registerProviderQueues([provider])
    standalone.set(provider, registration)
  } else registration.update(0, provider.requestPolicy)
  return registration.queues[0]
}

export function providerQueueStats(): ProviderQueueStats[] {
  return [...queues.values()].filter((queue) => queue.visible()).map((queue) => queue.snapshot())
}

/** Capped exponential backoff with 0–20% positive jitter. */
export function retryDelay(attempt: number, initial: number, maximum: number, random = Math.random()): number {
  const ceiling = Math.min(maximum, initial * 2 ** Math.min(attempt, 30))
  return Math.min(maximum, Math.ceil(ceiling * (1 + random * 0.2)))
}
