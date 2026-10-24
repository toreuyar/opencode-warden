/**
 * Server-side bridge for Warden's optional TUI notification companion.
 *
 * Wiring contract (minimal, for the integrator who owns src/index.ts):
 *
 *   let notificationsEnabled = false
 *   const notificationBridge = createWardenNotificationBridge({
 *     rpc: ctx.rpc,
 *     enabled: () => notificationsEnabled,
 *   })
 *
 *   const client: PluginClient = {
 *     ...
 *     tui: {
 *       // Replace the existing no-op with the bridge. Existing hooks keep
 *       // their own canToast/rate-limit checks and message call sites.
 *       showToast: (input) => notificationBridge.showToast(input),
 *     },
 *   }
 *
 *   // After loadConfig succeeds:
 *   notificationsEnabled = config.notifications
 *
 *   // In the existing setup cleanup:
 *   void notificationBridge.dispose()
 *
 * The bridge is deliberately fire-and-forget:
 * - RPC registration never blocks plugin setup. Notifications emitted before
 *   registration resolves are held in a small bounded queue.
 * - Registration, emission, and disposal failures are swallowed (optionally
 *   reported through onFailure) so a missing TUI, an older host without RPC,
 *   or a disconnected client can never affect enforcement.
 * - showToast() does not await delivery, so a slow client cannot delay a
 *   security hook.
 */

import type { Plugin } from "@opencode/plugin"
import {
  sanitizeWardenNotification,
  WARDEN_NOTIFICATION_EVENT,
  WardenNotificationDefinition,
  type WardenNotification,
  type WardenNotificationInput,
} from "./rpc.js"

type ServerRpc = Parameters<Plugin.Plugin["setup"]>[0]["rpc"]

/** Maximum notifications retained before RPC registration completes. */
const MAX_PENDING_NOTIFICATIONS = 16

export interface WardenNotificationBridgeOptions {
  /** Server plugin RPC domain. Missing/undefined disables the bridge. */
  rpc?: Pick<ServerRpc, "register"> | null
  /** Evaluated for every notification so config changes are respected live. */
  enabled?: () => boolean
  /** Optional safe diagnostic sink. Must never receive raw payloads. */
  onFailure?: (message: string) => void
}

export interface WardenLegacyToastInput {
  body: {
    message: string
    variant?: string
  }
}

export interface WardenNotificationBridge {
  /** True once the event contract is registered with the server RPC domain. */
  readonly ready: boolean
  /** Emit a structured, sanitized notification. Never rejects. */
  notify(input: WardenNotificationInput): Promise<void>
  /** Adapter for the existing V1-shaped client.tui.showToast shim. Never rejects. */
  showToast(input: WardenLegacyToastInput): Promise<void>
  /** Unregister the RPC contract. Never rejects. */
  dispose(): Promise<void>
}

interface RegisteredNotifications {
  emit(notification: WardenNotification): Promise<void>
  dispose(): Promise<void>
}

/**
 * Classify an existing toast without forwarding its free-form text.
 *
 * Existing hooks build user-facing strings that may contain file paths or
 * model explanations. Only the class is retained; the message itself is
 * intentionally discarded before it can reach the event stream.
 */
export function notificationFromLegacyToast(
  input: WardenLegacyToastInput,
): WardenNotificationInput | null {
  const message = typeof input.body?.message === "string" ? input.body.message : ""
  if (message.length === 0) return null

  if (/output\s+(blocked|withheld)|withheld for safety|llm unreachable/i.test(message)) {
    return { kind: "withheld" }
  }
  if (/denied|\bdeny\b/i.test(message)) return { kind: "denied" }
  if (/redact/i.test(message)) {
    const match = /(\d+)\s+secret/i.exec(message)
    return {
      kind: "redacted",
      ...(match?.[1] === undefined ? {} : { count: Number(match[1]) }),
    }
  }
  if (/risk/i.test(message)) return { kind: "risk" }
  if (/blocked|\bblock\b/i.test(message)) return { kind: "blocked" }

  // Every remaining toast is still surfaced, but only as the fixed generic
  // warning class. The original text is never carried into the event.
  return { kind: "warning" }
}

export function createWardenNotificationBridge(
  options: WardenNotificationBridgeOptions = {},
): WardenNotificationBridge {
  const enabled = options.enabled ?? (() => true)
  const report = (message: string) => {
    try {
      options.onFailure?.(message)
    } catch {
      // Diagnostics must not affect enforcement or the RPC bridge.
    }
  }

  let registration: RegisteredNotifications | null = null
  let registrationPending = Boolean(options.rpc)
  let disposed = false
  const queued: WardenNotification[] = []

  const deliver = (active: RegisteredNotifications, notification: WardenNotification): void => {
    void active.emit(notification).catch(() => {
      report("Warden notification delivery failed")
    })
  }

  if (options.rpc) {
    try {
      const pending = options.rpc.register(WardenNotificationDefinition, {})
      void pending.then(
        (result) => {
          const active: RegisteredNotifications = {
            emit: (notification) =>
              result.events.emit(WARDEN_NOTIFICATION_EVENT, notification),
            dispose: () => result.dispose(),
          }
          registrationPending = false
          if (disposed) {
            void active.dispose().catch(() => {
              report("Warden notification RPC disposal failed")
            })
            return
          }
          registration = active
          for (const notification of queued.splice(0)) deliver(active, notification)
        },
        () => {
          registrationPending = false
          queued.length = 0
          report("Warden notification RPC registration failed; notifications disabled")
        },
      )
    } catch {
      registrationPending = false
      report("Warden notification RPC registration failed; notifications disabled")
    }
  }

  const isEnabled = (): boolean => {
    try {
      return enabled()
    } catch {
      return false
    }
  }

  const notify = async (input: WardenNotificationInput): Promise<void> => {
    if (!isEnabled()) return
    const notification = sanitizeWardenNotification(input)
    if (!notification) return

    const active = registration
    if (active) {
      try {
        await active.emit(notification)
      } catch {
        report("Warden notification delivery failed")
      }
      return
    }

    if (!registrationPending) return
    if (queued.length >= MAX_PENDING_NOTIFICATIONS) queued.shift()
    queued.push(notification)
  }

  return {
    get ready() {
      return registration !== null
    },
    notify,
    async showToast(input) {
      const notification = notificationFromLegacyToast(input)
      if (notification) void notify(notification)
    },
    async dispose() {
      disposed = true
      queued.length = 0
      const active = registration
      registration = null
      if (!active) return
      try {
        await active.dispose()
      } catch {
        report("Warden notification RPC disposal failed")
      }
    },
  }
}
