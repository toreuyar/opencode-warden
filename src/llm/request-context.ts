import { AsyncLocalStorage } from "node:async_hooks"
import type { LlmRequestFailure } from "../types.js"

export function requestFailureMessage(reason: LlmRequestFailure): string {
  return reason === "deadline"
    ? "Warden: LLM evaluation deadline exceeded — operation blocked; retry later."
    : "Warden: LLM evaluation cancelled — operation blocked."
}

const requestErrorBrand = Symbol.for("opencode-warden.request-error.v1")
export class LlmRequestError extends Error {
  readonly [requestErrorBrand] = true
  static [Symbol.hasInstance](value: unknown): boolean {
    return value instanceof Error && (value as unknown as Record<symbol, unknown>)[requestErrorBrand] === true
  }
  constructor(readonly reason: LlmRequestFailure) {
    super(requestFailureMessage(reason))
  }
}

export class LlmInferenceTimeoutError extends Error {
  constructor() { super("LLM inference request timed out") }
}

interface RequestScope {
  id: string
  signal: AbortSignal
  deadline: number
}

const storage = new AsyncLocalStorage<RequestScope>()
export const currentLlmRequest = () => storage.getStore()

export function checkRequest(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw signal.reason instanceof LlmRequestError ? signal.reason : new LlmRequestError("cancelled")
  }
}

export async function withLlmRequest<T>(
  options: { signal?: AbortSignal; timeoutMs: number },
  run: () => Promise<T>,
): Promise<T> {
  const parent = currentLlmRequest()
  const controller = new AbortController()
  const deadline = Math.min(Date.now() + options.timeoutMs, parent?.deadline ?? Infinity)
  const signals = [options.signal, parent?.signal].filter((signal): signal is AbortSignal => !!signal)
  const cancel = () => controller.abort(new LlmRequestError("cancelled"))
  const listeners = signals.map((signal) => {
    const abort = () => controller.abort(
      signal.reason instanceof LlmRequestError ? signal.reason : new LlmRequestError("cancelled"),
    )
    signal.addEventListener("abort", abort, { once: true })
    if (signal.aborted) abort()
    return () => signal.removeEventListener("abort", abort)
  })
  const timer = setTimeout(() => controller.abort(new LlmRequestError("deadline")), Math.max(0, deadline - Date.now()))
  try {
    checkRequest(controller.signal)
    if (deadline <= Date.now()) throw new LlmRequestError("deadline")
    const result = await storage.run({ id: parent?.id ?? crypto.randomUUID(), signal: controller.signal, deadline }, run)
    checkRequest(controller.signal)
    if (Date.now() >= deadline) throw new LlmRequestError("deadline")
    return result
  } finally {
    clearTimeout(timer)
    for (const remove of listeners) remove()
    // Abort any accidentally detached work when its scope has ended.
    cancel()
  }
}

export function waitForRetry(ms: number, signal: AbortSignal): Promise<void> {
  checkRequest(signal)
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer)
      signal.removeEventListener("abort", abort)
      try { checkRequest(signal) } catch (error) { reject(error) }
    }
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort)
      resolve()
    }, ms)
    signal.addEventListener("abort", abort, { once: true })
    if (signal.aborted) abort()
  })
}

/** Hook events have no AbortSignal in the V2 Promise SDK. Lifecycle events
 * cancel outstanding scopes; later requests get a fresh controller.
 */
export function createRequestLifecycle() {
  const sessions = new Map<string, AbortController>()
  const shutdown = new AbortController()
  return {
    signal(sessionID: string): AbortSignal {
      if (shutdown.signal.aborted) return shutdown.signal
      let controller = sessions.get(sessionID)
      if (!controller) {
        controller = new AbortController()
        sessions.set(sessionID, controller)
      }
      return controller.signal
    },
    cancel(sessionID: string): void {
      sessions.get(sessionID)?.abort(new LlmRequestError("cancelled"))
      sessions.delete(sessionID)
    },
    dispose(): void {
      shutdown.abort(new LlmRequestError("cancelled"))
      for (const controller of sessions.values()) controller.abort(new LlmRequestError("cancelled"))
      sessions.clear()
    },
  }
}
