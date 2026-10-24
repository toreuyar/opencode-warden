/**
 * Public RPC contract for Warden's optional TUI notification companion.
 *
 * This module is intentionally pure: it contains no server enforcement code,
 * no audit-log reader, and no UI. It is safe for a TUI plugin (or any other
 * client) to import without loading Warden's server plugin.
 *
 * Security boundary:
 * - Events carry only a closed notification kind plus optional, bounded
 *   metadata (tool name and redaction count).
 * - Events never carry raw tool input/output, file contents, paths, reasons,
 *   LLM explanations, or audit records.
 * - The TUI renders fixed messages from the kind; it makes no security
 *   decisions and cannot allow/deny anything.
 */

import type { Rpc } from "@opencode/plugin/rpc"
import { z } from "zod"

export const WARDEN_NOTIFICATION_RPC_ID = "opencode-warden.notifications"
export const WARDEN_NOTIFICATION_EVENT = "notification"
export const WARDEN_NOTIFICATION_VERSION = 1

/**
 * Stable, bounded notification classes. The client maps these to fixed text;
 * the server must not attach free-form messages.
 */
export const WARDEN_NOTIFICATION_KINDS = [
  "blocked",
  "denied",
  "redacted",
  "withheld",
  "risk",
  "warning",
] as const

export type WardenNotificationKind = (typeof WARDEN_NOTIFICATION_KINDS)[number]

const SAFE_TOOL_NAME = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/
const MAX_COUNT = 1_000_000

export const wardenNotificationSchema = z
  .object({
    version: z.literal(WARDEN_NOTIFICATION_VERSION),
    kind: z.enum(WARDEN_NOTIFICATION_KINDS),
    /** Canonical tool identifier only. Never arguments, paths, or output. */
    tool: z.string().regex(SAFE_TOOL_NAME).optional(),
    /** Redaction/detection count only. */
    count: z.number().int().min(0).max(MAX_COUNT).optional(),
  })
  .strict()

export type WardenNotification = z.infer<typeof wardenNotificationSchema>

/** Input accepted by the server-side emitter before normalization. */
export interface WardenNotificationInput {
  kind: WardenNotificationKind
  tool?: string
  count?: number
}

/**
 * Portable RPC definition shared by the server bridge and the TUI client.
 *
 * It intentionally has no methods: the bridge is event-only. In particular,
 * the TUI has no RPC path that could influence enforcement.
 */
export const WardenNotificationDefinition = {
  id: WARDEN_NOTIFICATION_RPC_ID,
  methods: {},
  events: {
    [WARDEN_NOTIFICATION_EVENT]: { schema: wardenNotificationSchema },
  },
} satisfies Rpc.PortableDefinition

const KIND_SET: ReadonlySet<string> = new Set(WARDEN_NOTIFICATION_KINDS)

function sanitizeToolName(value: unknown): string | undefined {
  if (typeof value !== "string" || !SAFE_TOOL_NAME.test(value)) return undefined
  return value
}

function sanitizeCount(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined
  return Math.min(Math.max(Math.trunc(value), 0), MAX_COUNT)
}

/**
 * Convert untrusted input into the strict event shape. Unsafe optional fields
 * are dropped rather than rejecting the whole notification.
 *
 * Returns null only when the kind is missing or outside the closed set.
 */
export function sanitizeWardenNotification(input: unknown): WardenNotification | null {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return null
  const record = input as Record<string, unknown>
  if (typeof record.kind !== "string" || !KIND_SET.has(record.kind)) return null

  const tool = sanitizeToolName(record.tool)
  const count = sanitizeCount(record.count)
  return {
    version: WARDEN_NOTIFICATION_VERSION,
    kind: record.kind as WardenNotificationKind,
    ...(tool === undefined ? {} : { tool }),
    ...(count === undefined ? {} : { count }),
  }
}
