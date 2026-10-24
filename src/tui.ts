/**
 * Optional OpenCode TUI companion for Warden.
 *
 * Loaded by the TUI as the package's `tui` entrypoint. It subscribes to the
 * public server RPC event contract in ./rpc.ts and renders notifications.
 *
 * Non-negotiables:
 * - No enforcement logic and no allow/deny calls live here.
 * - No raw server messages, payloads, paths, or audit records are rendered.
 * - Missing server RPC, an unavailable TUI toast/attention API, or malformed
 *   event data is ignored; none of it can throw into the TUI runtime.
 */

import type { Plugin } from "@opencode/plugin/tui"
import {
  sanitizeWardenNotification,
  WARDEN_NOTIFICATION_EVENT,
  WARDEN_NOTIFICATION_VERSION,
  WardenNotificationDefinition,
  type WardenNotification,
  type WardenNotificationKind,
} from "./rpc.js"

type TuiContext = Parameters<Plugin.Definition["setup"]>[0]
type TuiBridgeContext = Pick<TuiContext, "client" | "ui" | "attention">

export interface WardenTuiToast {
  title: string
  message: string
  variant: "info" | "success" | "warning" | "error"
}

const CRITICAL_KINDS: ReadonlySet<WardenNotificationKind> = new Set([
  "blocked",
  "denied",
  "withheld",
])

/** Fixed client-side copy. The event cannot supply free-form text. */
export function toastForWardenNotification(notification: WardenNotification): WardenTuiToast {
  const suffix = notification.tool ? ` (${notification.tool})` : ""
  switch (notification.kind) {
    case "blocked":
      return { title: "Warden", message: `🛡 Warden blocked a tool call${suffix}`, variant: "error" }
    case "denied":
      return { title: "Warden", message: `🛡 Warden denied a permission request${suffix}`, variant: "error" }
    case "redacted": {
      const count = notification.count
      const secrets = count === undefined || count === 0
        ? "sensitive data"
        : count === 1 ? "1 secret" : `${count} secrets`
      return { title: "Warden", message: `🔒 Warden redacted ${secrets}${suffix}`, variant: "warning" }
    }
    case "withheld":
      return { title: "Warden", message: `🛡 Warden withheld tool output${suffix}`, variant: "error" }
    case "risk":
      return { title: "Warden", message: `⚠️ Warden detected elevated risk${suffix}`, variant: "warning" }
    case "warning":
      return { title: "Warden", message: `⚠️ Warden security warning${suffix}`, variant: "warning" }
  }
}

export interface WardenTuiNotifications {
  dispose(): void
}

/**
 * Subscribe the TUI to Warden notification events.
 *
 * Exported separately from the plugin default so it can be tested without
 * loading @opentui/solid or a live OpenCode client.
 */
export function registerWardenTuiNotifications(context: TuiBridgeContext): WardenTuiNotifications {
  let unsubscribe: (() => void) | null = null

  try {
    const rpc = context.client.rpc(WardenNotificationDefinition)
    unsubscribe = rpc.events.on(WARDEN_NOTIFICATION_EVENT, (event) => {
      try {
        const record = event.data as unknown
        if (
          typeof record !== "object" ||
          record === null ||
          (record as { version?: unknown }).version !== WARDEN_NOTIFICATION_VERSION
        ) {
          return
        }

        const notification = sanitizeWardenNotification(record)
        if (!notification) return
        const toast = toastForWardenNotification(notification)

        try {
          context.ui.toast.show(toast)
        } catch {
          // A broken toast renderer must not prevent the optional system
          // notification from being attempted.
        }

        if (!CRITICAL_KINDS.has(notification.kind)) return
        void context.attention.notify({
          title: toast.title,
          message: toast.message,
          notification: { when: "blurred" },
        }).catch(() => {
          // Desktop notifications are optional and may be disabled.
        })
      } catch {
        // Malformed events and unavailable UI APIs are ignored by design.
      }
    })
  } catch {
    // Older hosts, disconnected clients, or unsupported RPC leave the TUI
    // silent. Warden enforcement is unaffected.
  }

  return {
    dispose() {
      const active = unsubscribe
      unsubscribe = null
      if (!active) return
      try {
        active()
      } catch {
        // Subscription cleanup is best-effort.
      }
    },
  }
}

const plugin: Plugin.Definition = {
  id: "opencode.warden.notifications",
  setup(context) {
    try {
      return registerWardenTuiNotifications(context).dispose
    } catch {
      return
    }
  },
}

export default plugin
