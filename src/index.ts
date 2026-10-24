import { Plugin } from "@opencode/plugin"
import { join } from "path"
import { loadConfig } from "./config/index.js"
import { createDetectionEngine } from "./detection/index.js"
import { AuditLogger, SessionStats, DiagnosticLogger, LlmChatLogger } from "./audit/index.js"
import { LlmSanitizer, SafetyEvaluator, OutputTriageEvaluator, OutputTextTriageEvaluator, ProviderChain } from "./llm/index.js"
import { createInputSanitizer } from "./hooks/input-sanitizer.js"
import { createOutputRedactor } from "./hooks/output-redactor.js"
import { createPermissionHandler } from "./hooks/permission-handler.js"
import { createEnvSanitizer } from "./hooks/env-sanitizer.js"
import { createCompactionContext } from "./hooks/compaction-context.js"
import { createPromptSanitizer } from "./hooks/prompt-sanitizer.js"
import { createOutboundSanitizer } from "./hooks/outbound-sanitizer.js"
import { createShellBackstop } from "./hooks/shell-backstop.js"
import { removeBlockedRequestTools, removeBlockedTransformTools } from "./hooks/tool-surface.js"
import { sweepStaleSessions } from "./hooks/session-context.js"
import { createSessionPermissionSync } from "./hooks/session-permissions.js"
import { buildSecurityPolicyContext } from "./hooks/security-policy.js"
import { createWardenNotificationBridge, type WardenNotificationBridge } from "./tui-notifications.js"
import {
  createExecuteAfterAdapter,
  createPermissionAdapter,
  registerFailClosedHooks,
  type PermissionEvaluationEvent,
  type ToolAfterEvent,
} from "./hooks/v2-adapters.js"
import { createSecurityDashboardTool } from "./tools/security-dashboard.js"
import { createSecurityReportTool } from "./tools/security-report.js"
import { createRulesManageTool } from "./tools/rules-manage.js"
import { createSecurityHelpTool } from "./tools/security-help.js"
import { createSecurityAuditTool } from "./tools/security-audit.js"
import { createSecurityEvaluateTool } from "./tools/security-evaluate.js"
import { createSecurityConfigTool } from "./tools/security-config.js"
import type {
  ToastState,
  PatternCategory,
  PermissionRule,
  PluginClient,
  WrittenFileMetadata,
} from "./types.js"

// ─────────────────────────────────────────────────────────────────────────────
// OpenCode v2 plugin (API: @opencode/plugin, Plugin.define + setup(ctx)).
//
// Ported from the V1 implementation (v1.3.0, hook-map style). ALL V1→V2
// bridging lives in THIS file; the security modules (detection, hooks, llm,
// audit, config, utils) are unchanged and receive V1-shaped (input, output)
// arguments through thin adapters below.
//
// V1 → V2 mapping used here:
//   tool.execute.before            → ctx.tool.hook("execute.before")
//   tool.execute.after             → ctx.tool.hook("execute.after")
//   permission.ask                 → ctx.permission.hook("evaluate")
//   shell.env                      → ctx.shell.hook("create.before")
//   experimental.session.compacting→ ctx.session.hook("compaction")
//   chat.message                   → ctx.session.hook("prompt")
//   event (hook)                   → ctx.event.subscribe()
//   tool map (tool({...}))         → ctx.tool.transform(editor.add({...}))
//   client.session.prompt(noReply) → ctx.session.synthetic() (permission
//                                    denial text only; policy is NOT synthetic)
//   security-policy injection      → ctx.session.hook("context") system part
//                                    (per request; never durable history)
//   client.app.log                 → console (server log; no app.log API in v2)
//   client.tui.showToast           → src/tui-notifications.ts RPC bridge
//                                    (sanitized event-only; UX-only, never enforcement)
//   directory                      → ctx.location.directory
//
// Behavioral notes:
//  - The v2 prompt hook does NOT run for synthetic messages. Those are now used
//    only for permission denial text; security policy is a per-request system
//    part appended by the context hook.
//  - v2 PermissionEvaluation carries canonical targets in `resources` and the
//    call identity in `source`; shell metadata.command is not always present.
//  - Tool results in v2 are Tool.Result ({output?, content?, metadata?}); the
//    output redactor works on the textual content and writes it back.
// ─────────────────────────────────────────────────────────────────────────────

// Supported host floor. Bounded runtime validation of the built plugin passed on
// OpenCode 2.0.18, and the V2 API surface Warden uses is present in the 2.0.18
// `@opencode/plugin` package. `@opencode/plugin` 2.0.29 introduced the typed
// `Tool.Error` mapping for `execute.before` rejections; 2.0.18-2.0.28 still abort
// the blocked call, but through the older untyped per-call rejection path that
// was exercised on 2.0.18. The peer dependency declares the API floor
// (`^2.0.18`); typed-veto behavior is a host-runtime property from 2.0.29.
export const MIN_SUPPORTED_OPENCODE_VERSION = "2.0.18"
export const TYPED_TOOL_VETO_OPENCODE_VERSION = "2.0.29"
/** Backward-compatible alias for the minimum supported host floor. */
export const SUPPORTED_OPENCODE_VERSION = MIN_SUPPORTED_OPENCODE_VERSION

interface ParsedRuntimeVersion {
  major: number
  minor: number
  patch: number
}

/** Parse a leading `vX.Y.Z` runtime version; null when the shape is unknown. */
export function parseRuntimeVersion(version: string): ParsedRuntimeVersion | null {
  const match = /^\s*v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?\s*$/.exec(version)
  if (!match) return null
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  }
}

function meetsFloor(version: ParsedRuntimeVersion, floor: string): boolean {
  const minimum = parseRuntimeVersion(floor)
  if (!minimum) return false
  if (version.major !== minimum.major) return version.major > minimum.major
  if (version.minor !== minimum.minor) return version.minor > minimum.minor
  return version.patch >= minimum.patch
}

/**
 * Whether a runtime version meets the supported floor. Returns null when the
 * version cannot be parsed, so callers only warn on a coherent comparison.
 */
export function isRuntimeVersionSupported(version: string): boolean | null {
  const parsed = parseRuntimeVersion(version)
  if (!parsed) return null
  return meetsFloor(parsed, MIN_SUPPORTED_OPENCODE_VERSION)
}

/**
 * Whether a runtime maps `execute.before` rejections to a typed `Tool.Error`.
 * Returns null when the version cannot be parsed. This is behavioral, not an
 * additional support floor: older supported hosts still block per-call.
 */
export function isTypedToolVetoSupported(version: string): boolean | null {
  const parsed = parseRuntimeVersion(version)
  if (!parsed) return null
  return meetsFloor(parsed, TYPED_TOOL_VETO_OPENCODE_VERSION)
}

/**
 * Build the version diagnostic. Never used to refuse activation: the runtime
 * probe proved that a failed setup drops every Warden hook and the host
 * continues unprotected.
 */
export function runtimeCompatibilityWarning(version: string): string | null {
  const supported = isRuntimeVersionSupported(version)
  if (supported === null) return null
  if (supported === false) {
    return (
      `Warden: OpenCode ${version} is below the supported runtime floor ` +
      `${MIN_SUPPORTED_OPENCODE_VERSION}. Protections remain installed and active, but ` +
      `host compatibility is not guaranteed. Typed per-call tool vetoes require ` +
      `${TYPED_TOOL_VETO_OPENCODE_VERSION}+; supported 2.0.18-2.0.28 hosts block ` +
      `through the untyped per-call rejection path.`
    )
  }
  if (isTypedToolVetoSupported(version) === false) {
    return (
      `Warden: OpenCode ${version} meets the supported runtime floor ` +
      `${MIN_SUPPORTED_OPENCODE_VERSION}, but typed per-call tool vetoes require ` +
      `${TYPED_TOOL_VETO_OPENCODE_VERSION}+. Warden blocks through the older untyped ` +
      `per-call rejection path, which was tested on 2.0.18. Protections remain ` +
      `installed and active.`
    )
  }
  return null
}

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" ? (value as Record<string, unknown>) : {}

const sessionIDFromEvent = (event: unknown): string => {
  if (!event || typeof event !== "object") return ""
  const data = (event as { data?: unknown }).data
  if (!data || typeof data !== "object") return ""
  const record = data as Record<string, unknown>
  if (typeof record.sessionID === "string" && record.sessionID.length > 0) return record.sessionID
  const info = record.info
  if (info && typeof info === "object") {
    const id = (info as Record<string, unknown>).id
    if (typeof id === "string" && id.length > 0) return id
  }
  return ""
}

export default Plugin.define({
  id: "opencode-warden",
  async setup(ctx) {
    let notificationsEnabled = false
    let notificationBridge: WardenNotificationBridge | null = null
    let disposeResources: (() => void) | null = null

    try {
      const directory = ctx.location.directory

      // ─── TUI/RPC notification bridge ───
      // UX-only. Registration/delivery failure never affects enforcement. The
      // enablement flag is updated after config loads so `notifications: false`
      // suppresses both startup and hook notifications without changing hook
      // call sites or their existing rate limiting.
      notificationBridge = createWardenNotificationBridge({
        rpc: ctx.rpc,
        enabled: () => notificationsEnabled,
        onFailure: (message) => {
          try {
            console.warn(`[warden] ${message}`)
          } catch {
            /* console failure is non-critical */
          }
        },
      })
      const bridge = notificationBridge

      // ─── V1 client shim ───
      // v2 plugins talk to domains on ctx directly; the security modules expect
      // the narrow PluginClient surface (app.log / session.prompt / tui.toast).
      const client: PluginClient = {
        app: {
          log: async ({ body }) => {
            // v2 has no app.log API — console output lands in the server log.
            const line = `[warden] ${body.level}: ${body.message}`
            if (body.level === "error") console.error(line)
            else if (body.level === "warn") console.warn(line)
            else console.log(line)
          },
        },
        session: {
          prompt: async ({ path, body }) => {
            // v1 sent a noReply parts message; v2 equivalent is a synthetic
            // message (which also bypasses the prompt hook by design).
            const text = body.parts
              .map((part) => {
                const candidate = (part as { text?: unknown }).text
                return typeof candidate === "string" ? candidate : ""
              })
              .filter((text) => text.length > 0)
              .join("\n\n")
            await ctx.session.synthetic({ sessionID: path.id, text })
          },
        },
        tui: {
          // Every existing hook toast goes through the RPC bridge. The bridge
          // keeps only a closed-class kind and bounded metadata; raw messages,
          // paths, and explanations never reach the TUI.
          showToast: (input) => bridge.showToast(input),
        },
      }

    // ─── Load Configuration ───
    // Inline plugin options are validated only when no global/project config
    // file exists (file sources always win; see src/config/index.ts).
    let loadedConfig: ReturnType<typeof loadConfig>
    try {
      loadedConfig = loadConfig(directory, { inlineConfig: ctx.options })
    } catch {
      // Never throw out of setup: OpenCode drops a failed plugin, leaving no
      // Warden hooks at all. Install the deny-all lockdown instead. The error
      // itself is not logged because loader errors could echo configured values.
      notificationsEnabled = false
      try {
        await bridge.dispose()
      } catch {
        /* notification failure is non-critical */
      }
      try {
        await registerFailClosedHooks(ctx, {
          source: "loader",
          code: "WARDEN_CONFIG_FAILURE",
          message: "configuration loader failed unexpectedly",
        })
      } catch {
        // Nothing further can be installed; the host will surface setup failure.
      }
      return () => {}
    }

    const { config, warnings: configWarnings, failure: configFailure } = loadedConfig
    notificationsEnabled = config.notifications
    if (configFailure) {
      // Authoritative failure branch. Do NOT construct LLM providers/chains or
      // install normal hooks with the loader's defensive shell config.
      notificationsEnabled = false
      try {
        await bridge.dispose()
      } catch {
        /* notification failure is non-critical */
      }
      try {
        await registerFailClosedHooks(ctx, configFailure)
      } catch {
        // Registration is the only remaining protection; keep setup from
        // throwing so an already-registered subset still applies.
      }
      return () => {}
    }

    const startupWarnings: string[] = [...configWarnings]

    // ─── Create Detection Engine ───
    const engine = createDetectionEngine(config, startupWarnings)

    // ─── Resolve audit log path ───
    const resolvedAuditConfig = {
      ...config.audit,
      filePath: config.audit.filePath.startsWith("/")
        ? config.audit.filePath
        : join(directory, config.audit.filePath),
    }

    // ─── Create Audit Logger ───
    const auditLogger = new AuditLogger(resolvedAuditConfig, client)

    // ─── Create Diagnostic Logger (independent of LLM) ───
    let diagnosticLogger: DiagnosticLogger | null = null
    let llmChatLogger: LlmChatLogger | undefined
    if (config.diagnosticLog.enabled) {
      const resolvedDiagPath = config.diagnosticLog.filePath.startsWith("/")
        ? config.diagnosticLog.filePath
        : join(directory, config.diagnosticLog.filePath)
      diagnosticLogger = new DiagnosticLogger({
        ...config.diagnosticLog,
        filePath: resolvedDiagPath,
      })
      // LLM chat log: separate file in the same directory
      const llmChatPath = resolvedDiagPath.replace(/\.log$/, "-llm.log")
      llmChatLogger = new LlmChatLogger({
        filePath: llmChatPath,
        maxFileSize: config.diagnosticLog.maxFileSize,
        maxFiles: config.diagnosticLog.maxFiles,
      })
    }

    // ─── Create LLM Components (if enabled) ───
    let debugLog: ((msg: string) => void) | undefined
    let sanitizerChain: ProviderChain | null = null
    let safetyChain: ProviderChain | null = null
    let outputTriage: OutputTriageEvaluator | null = null
    let outputTextTriage: OutputTextTriageEvaluator | null = null

    if (config.llm.enabled) {
      // Panel-based debug log (existing behavior)
      const panelDebugLog = config.llm.debug
        ? (msg: string) => {
            client.app.log({
              body: { service: "warden", level: "info", message: msg },
            }).catch(() => {})
          }
        : undefined

      // File-based debug log for diagnostic file
      const fileDebugLog = diagnosticLogger
        ? (msg: string) => diagnosticLogger!.info(msg)
        : undefined

      // Combined: call both if either exists
      debugLog = (panelDebugLog || fileDebugLog)
        ? (msg: string) => { panelDebugLog?.(msg); fileDebugLog?.(msg) }
        : undefined

      // Build ProviderChain instances from resolved config
      // Each component uses its own providers (already resolved by config inheritance)
      sanitizerChain = new ProviderChain(config.llm.outputSanitizer.providers, debugLog, llmChatLogger)
      safetyChain = new ProviderChain(config.llm.safetyEvaluator.providers, debugLog, llmChatLogger)

      if (config.llm.outputTriage.enabled) {
        const triageChain = new ProviderChain(config.llm.outputTriage.providers, debugLog, llmChatLogger)
        outputTriage = new OutputTriageEvaluator(config.llm.outputTriage, triageChain, debugLog)
      }

      if (config.llm.outputTextTriage.enabled) {
        const textTriageChain = new ProviderChain(config.llm.outputTextTriage.providers, debugLog, llmChatLogger)
        outputTextTriage = new OutputTextTriageEvaluator(config.llm.outputTextTriage, textTriageChain, debugLog)
      }

      // Health check (non-blocking — don't block plugin startup)
      sanitizerChain.healthCheck().then((healthy) => {
        if (!healthy) {
          client.app.log({
            body: {
              service: "warden",
              level: "error",
              message:
                "LLM unreachable — all LLM-evaluated operations will be BLOCKED until LLM is available",
            },
          }).catch(() => {})

          if (config.notifications) {
            client.tui.showToast({
              body: {
                message: "🛡 Warden: LLM unreachable — LLM-evaluated operations will be BLOCKED",
                variant: "error",
              },
            }).catch(() => {})
          }
        }
      })

      // Triage health checks (non-blocking)
      if (outputTriage) {
        outputTriage.healthCheck().catch(() => {})
      }
      if (outputTextTriage) {
        outputTextTriage.healthCheck().catch(() => {})
      }
    }

    // ─── Session-Scoped State ───
    const securityPolicyText = buildSecurityPolicyContext(config)

    interface SessionSecurityState {
      sessionStats: SessionStats
      toastState: ToastState
      sessionAllowlist: Set<string>
      evaluatedCalls: Set<string>
      writtenFileRegistry: Map<string, WrittenFileMetadata>
      llmSanitizer: LlmSanitizer | null
      safetyEvaluator: SafetyEvaluator | null
      lastAccessed: number
    }

    const sessions = new Map<string, SessionSecurityState>()
    let latestSessionID = "__default__"

    // TTL: sessions whose lastAccessed is older than this are eligible for sweep.
    // 24h is well beyond any reasonable "user stepped away" window — even full
    // workdays. The only cost of sweeping an actually-still-alive session is
    // re-injecting the policy and resetting sessionStats, both harmless.
    const SESSION_TTL_MS = 24 * 60 * 60 * 1000
    const SESSION_SWEEP_INTERVAL_MS = 60 * 60 * 1000 // hourly

    const createSessionState = (sessionID: string): SessionSecurityState => ({
      sessionStats: new SessionStats(sessionID === "__default__" ? "" : sessionID),
      toastState: {
        lastToastTime: 0,
        minInterval: 2000, // Max 1 toast per 2 seconds, per session
      },
      sessionAllowlist: new Set<string>(),
      evaluatedCalls: new Set<string>(),
      writtenFileRegistry: new Map<string, WrittenFileMetadata>(),
      llmSanitizer: config.llm.enabled && sanitizerChain
        ? new LlmSanitizer(config.llm, sanitizerChain, debugLog)
        : null,
      safetyEvaluator: config.llm.enabled && safetyChain
        ? new SafetyEvaluator(config.llm, safetyChain, debugLog, config.indirectExecution)
        : null,
      lastAccessed: Date.now(),
    })

    const getSessionState = (sessionID: string): SessionSecurityState => {
      const id = sessionID || "__default__"
      let state = sessions.get(id)
      if (!state) {
        state = createSessionState(id)
        sessions.set(id, state)
      }
      state.lastAccessed = Date.now()
      latestSessionID = id
      return state
    }

    const getLatestSessionState = () => getSessionState(latestSessionID)

    const resetSessionState = (sessionID: string): void => {
      const id = sessionID || "__default__"
      sessions.set(id, createSessionState(id))
      latestSessionID = id
    }

    // ─── Create Hooks ───
    const inputSanitizer = createInputSanitizer({
      engine,
      config,
      auditLogger,
      projectDir: directory,
      client,
      diagnosticLogger,
      getSessionState,
    })

    const outputRedactor = createOutputRedactor({
      engine,
      config,
      auditLogger,
      projectDir: directory,
      client,
      outputTriage,
      outputTextTriage,
      diagnosticLogger,
      getSessionState,
    })

    const envSanitizer = createEnvSanitizer({
      engine,
      config,
      auditLogger,
      sessionStats: getLatestSessionState().sessionStats,
      client,
      toastState: getLatestSessionState().toastState,
      diagnosticLogger,
    })

    const promptSanitizer = createPromptSanitizer({
      engine,
      config,
      auditLogger,
      client,
      diagnosticLogger,
      getSessionState,
    })

    const permissionHandler = createPermissionHandler({
      config,
      client,
      projectDir: directory,
      auditLogger,
      diagnosticLogger,
      getSessionState,
    })

    // Deterministic pre-provider outbound layer. The policy text is stable and
    // is appended per request (never written to stored history). No LLM calls
    // are made here; redactionEnabled/redactionExemptPaths still apply.
    const outboundSanitizer = createOutboundSanitizer({
      engine,
      config,
      projectDir: directory,
      policyText: securityPolicyText,
      auditLogger,
      diagnosticLogger,
    })

    // Compaction is another outbound request surface. Reuse the deterministic
    // scanner (policy injection included) over the native system/messages/tools
    // fields; unsupported shapes abort preparation (fail-closed).
    const compactionContext = createCompactionContext({
      config,
      diagnosticLogger,
      sanitizeRequest: (event, options) => outboundSanitizer(event, options),
    })

    // Global shell backstop. Runs for every shell spawn (including user
    // terminals), not just agent tool calls; no session identity or LLM.
    const shellBackstop = createShellBackstop({
      config,
      projectDir: directory,
      auditLogger,
      diagnosticLogger,
    })

    // Session-scoped deny rules are defense-in-depth only. They are synced on
    // `session.created` and lazily before the first tool/permission evaluation.
    // A failed read/update is logged and ignored; the primary guards below stay
    // authoritative. `session.update({ permissions })` replaces the ruleset, so
    // Warden re-reads and merges host rules first. The host has no
    // compare-and-set: a concurrent host write can still be overwritten (last
    // writer wins). The extra pre-write read narrows that race, and
    // `session.permissions` invalidation re-merges host changes on the next
    // sync; this is best-effort, never claimed as atomic.
    const sessionPermissionSync = createSessionPermissionSync({
      config,
      projectDir: directory,
      diagnosticLogger,
      getSessionPermissions: async (sessionID) => {
        if (typeof ctx.session.get !== "function") return null
        try {
          const info = await ctx.session.get({ sessionID: sessionID as never })
          return (info?.permissions as ReadonlyArray<PermissionRule> | undefined) ?? []
        } catch {
          return null
        }
      },
      updateSessionPermissions: async (sessionID, permissions) => {
        if (typeof ctx.session.update !== "function") {
          throw new Error("session.update unavailable")
        }
        await ctx.session.update({
          sessionID: sessionID as never,
          permissions: permissions as never,
        })
      },
    })

    // ─── Create Custom Tools ───
    const dashboardToolDef = createSecurityDashboardTool({
      getSessionStats: () => getLatestSessionState().sessionStats,
      config,
      getLlmSanitizer: () => getLatestSessionState().llmSanitizer,
    })

    const reportToolDef = createSecurityReportTool({
      getSessionStats: () => getLatestSessionState().sessionStats,
    })

    const rulesToolDef = createRulesManageTool({
      engine,
      config,
      projectDir: directory,
    })

    const helpToolDef = createSecurityHelpTool()

    const auditToolDef = createSecurityAuditTool({
      auditLogPath: resolvedAuditConfig.filePath,
      maxFiles: config.audit.maxFiles,
    })

    const evaluateToolDef = createSecurityEvaluateTool({
      getSafetyEvaluator: () => getLatestSessionState().safetyEvaluator,
    })

    const configToolDef = createSecurityConfigTool({ config })

    // ─── Log Startup ───
    const activeCategories = (
      Object.entries(config.categories) as [PatternCategory, boolean][]
    )
      .filter(([, enabled]) => enabled)
      .map(([cat]) => cat)

    const patternCount = engine.getPatterns().length

    client.app.log({
      body: {
        service: "warden",
        level: "info",
        message: `Warden active: ${patternCount} patterns, ${activeCategories.length} categories [${activeCategories.join(", ")}], LLM: ${config.llm.enabled ? "enabled" : "disabled"}`,
      },
    }).catch(() => {})

    diagnosticLogger?.startup(
      `Warden active: ${patternCount} patterns, ${activeCategories.length} categories, LLM: ${config.llm.enabled ? "enabled" : "disabled"}`,
      {
        categories: activeCategories,
        patternCount,
        llmEnabled: config.llm.enabled,
        diagnosticLog: config.diagnosticLog.filePath,
      },
    )

    // ─── Runtime Compatibility Diagnostic ───
    // Warn only; never refuse setup. A thrown setup() drops every Warden hook
    // and the host continues unprotected (verified in the 2.0.18 probe), so
    // refusing activation is not a security control.
    const runtimeVersion =
      typeof (ctx.app as { version?: unknown } | undefined)?.version === "string"
        ? ((ctx.app as { version: string }).version)
        : ""
    const runtimeWarning = runtimeVersion
      ? runtimeCompatibilityWarning(runtimeVersion)
      : null
    if (runtimeWarning) {
      try {
        console.warn(`[warden] ${runtimeWarning}`)
      } catch {
        /* console failure is non-critical */
      }
      client.app.log({
        body: { service: "warden", level: "warn", message: runtimeWarning },
      }).catch(() => {})
      diagnosticLogger?.info(runtimeWarning)
    }

    // ─── Show Startup Warnings ───
    for (const warning of startupWarnings) {
      client.app.log({
        body: { service: "warden", level: "warn", message: warning },
      }).catch(() => {})
      if (config.notifications) {
        client.tui.showToast({
          body: { message: `Config: ${warning}`, variant: "warning" as const },
        }).catch(() => {})
      }
    }

    // ─── Session State TTL Sweep ───
    // Sessions whose lastAccessed is older than SESSION_TTL_MS get swept hourly.
    // Bound the map's growth for long-lived plugin processes (e.g., a daemon
    // running for weeks). Active sessions are never swept — lastAccessed is
    // refreshed on every getSessionState call.
    const sweepTimer = setInterval(() => {
      try {
        const swept = sweepStaleSessions(sessions, Date.now(), SESSION_TTL_MS)
        if (swept.length > 0) {
          for (const sessionID of swept) sessionPermissionSync.forget(sessionID)
          diagnosticLogger?.info(`Session TTL sweep: removed ${swept.length} stale session(s)`, { swept })
          if (swept.includes(latestSessionID)) latestSessionID = "__default__"
        }
      } catch {
        // Sweep must never crash the runtime
      }
    }, SESSION_SWEEP_INTERVAL_MS)
    // Allow the Node/Bun process to exit even if the timer is still active
    if (typeof sweepTimer.unref === "function") sweepTimer.unref()

    // ─── Event Subscription (session lifecycle state resets) ───
    const eventController = new AbortController()
    disposeResources = () => {
      clearInterval(sweepTimer)
      eventController.abort()
    }
    void (async () => {
      for await (const event of ctx.event.subscribe({ signal: eventController.signal })) {
        try {
          if (event.type === "session.created") {
            const sessionID = sessionIDFromEvent(event)
            diagnosticLogger?.info(`Session reset: clearing state for ${sessionID || "default session"}`)
            resetSessionState(sessionID)
            // Drop any state from a prior incarnation, then best-effort sync.
            // The sync is non-authoritative; a later tool/permission evaluation
            // retries it lazily.
            sessionPermissionSync.forget(sessionID)
            void sessionPermissionSync.sync(sessionID)
          } else if (event.type === "session.deleted") {
            const sessionID = sessionIDFromEvent(event)
            sessionPermissionSync.forget(sessionID)
            if (sessionID && sessions.delete(sessionID)) {
              diagnosticLogger?.info(`Session deleted: removed state for ${sessionID}`)
              if (latestSessionID === sessionID) latestSessionID = "__default__"
            }
          } else if (event.type === "session.permissions") {
            // The host replaced the session ruleset. Invalidate the cache so
            // the next lazy sync re-reads it and re-appends Warden's rules
            // (which also avoids clobbering host additions next time). Our own
            // update emits this once; the follow-up read finds the rules
            // already present and performs no second update.
            sessionPermissionSync.forget(sessionIDFromEvent(event))
          }
        } catch {
          // Non-critical — event handler must never crash the runtime
        }
      }
    })().catch(() => {})

    // ─── Register V2 Hooks ───

    // session.context — deterministic pre-dispatch enforcement:
    //   1. append the stable security policy as a system part (per request,
    //      never stored in conversation history);
    //   2. remove blocked tools from this request's definitions by effective id
    //      (alias-aware, never touching surviving tool identity);
    //   3. scan outbound system/message text and redact detected secrets.
    // No synthetic message and no durable history mutation are involved.
    await ctx.session.hook("context", async (event) => {
      const removed = removeBlockedRequestTools(
        event.tools as Record<string, unknown>,
        config,
      )
      if (removed.length > 0) {
        diagnosticLogger?.info(
          `Outbound tool surface: removed ${removed.length} blocked tool(s): ${removed.join(", ")}`,
        )
      }
      await outboundSanitizer(event as unknown as Parameters<typeof outboundSanitizer>[0])
    })

    // session.generate — auxiliary model request that reuses the full session
    // context (agent, tools, system, messages). It is a distinct provider
    // surface and was previously unsanitized. Apply the same deterministic
    // outbound scan, policy append, and blocked-tool removal as `context`.
    await ctx.session.hook("generate", async (event) => {
      const removed = removeBlockedRequestTools(
        event.tools as Record<string, unknown>,
        config,
      )
      if (removed.length > 0) {
        diagnosticLogger?.info(
          `Outbound tool surface (generate): removed ${removed.length} blocked tool(s): ${removed.join(", ")}`,
        )
      }
      await outboundSanitizer(
        event as unknown as Parameters<typeof outboundSanitizer>[0],
        { surface: "generate" },
      )
    })

    // session.title — the initial/regenerated title request is a plain
    // SessionRequest (system + messages + options, no tools) and was previously
    // unsanitized, leaking the first user message/key to the provider. Scan and
    // redact it with the shared deterministic sanitizer. The security policy is
    // deliberately not appended: title generation is a narrow naming task and
    // extra instructions can change the title output. DLP applies regardless.
    await ctx.session.hook("title", async (event) => {
      await outboundSanitizer(
        event as unknown as Parameters<typeof outboundSanitizer>[0],
        { surface: "title", appendPolicy: false },
      )
    })

    // tool.execute.before — input sanitizer. The sanitizer blocks by throwing,
    // which v2 treats as tool-execution veto. Session permission rules are
    // synced first (and awaited) because this hook runs before
    // permission.evaluate; the sync itself is still defense-in-depth only.
    await ctx.tool.hook("execute.before", async (event) => {
      await sessionPermissionSync.sync(event.sessionID)
      getSessionState(event.sessionID)
      await inputSanitizer(
        { tool: event.tool, sessionID: event.sessionID, callID: event.id },
        { args: asRecord(event.input) },
      )
    })

    // tool.execute.after — output redaction over textual content, structured
    // output fallback, and error message/metadata sanitization.
    const executeAfter = createExecuteAfterAdapter({
      redactor: outputRedactor,
      engine,
    })
    await ctx.tool.hook("execute.after", (event) =>
      executeAfter(event as ToolAfterEvent),
    )

    // permission evaluate → shared permission handler. The adapter forwards the
    // real V2 action/resources/source call id and writes denial message/effect
    // back onto the mutable evaluation.
    const permissionAdapter = createPermissionAdapter(permissionHandler)
    await ctx.permission.hook("evaluate", async (event) => {
      // Fallback lazy sync for permission sources that bypass execute.before
      // (for example host-initiated assertions). The current event's effect was
      // already computed by the host, so this only narrows later evaluations;
      // the handler below is still the authoritative decision for this one.
      await sessionPermissionSync.sync(event.sessionID)
      return permissionAdapter(event as PermissionEvaluationEvent)
    })

    // shell.create.before — deterministic path/cwd backstop for every shell
    // spawn, followed by the existing env redaction/stripping. The backstop has
    // no sessionID (OpenCode does not provide one to this hook) and makes no
    // LLM calls. It intentionally also covers user-created shells, so a
    // configured blocked path cannot be reached through a terminal.
    await ctx.shell.hook("create.before", async (event) => {
      await shellBackstop({ command: event.command, cwd: event.cwd })
      await envSanitizer({ cwd: event.cwd }, { env: event.env as Record<string, string> })
    })

    // session.compaction — the native event carries the outbound summary
    // request (`system` / `messages` / `tools`). Sanitize it deterministically
    // and append the policy, preserving request/metadata/provider shapes.
    await ctx.session.hook("compaction", (event) =>
      compactionContext(event),
    )

    // chat.message → prompt hook. The sanitizer is block-only (throws on
    // detected secrets); a throw here prevents prompt admission in v2, matching
    // the v1 semantics where the throw aborted message creation.
    await ctx.session.hook("prompt", async (event) => {
      // The text and attachment metadata are both user-supplied and both reach
      // the provider. File attachment contents are deliberately not read here;
      // only the pre-materialization metadata (URI/name/description/mentions) is
      // scanned under the existing scanUserPrompts + redactionEnabled opt-in.
      await promptSanitizer(
        { sessionID: event.sessionID, messageID: event.messageID },
        {
          message: event.prompt,
          parts: [{ type: "text", text: event.prompt.text }],
          attachments: {
            files: event.prompt.files,
            agents: event.prompt.agents,
            skills: event.prompt.skills,
          },
        },
      )
    })

    // ─── Register Custom Tools ───
    await ctx.tool.transform((editor) => {
      editor.add({
        name: "security_help",
        description: helpToolDef.description,
        input: {
          type: "object",
          properties: {
            topic: { type: "string", description: "Tool name to get detailed help for" },
          },
          additionalProperties: false,
        },
        async execute(input) {
          return { content: await helpToolDef.execute(input as { topic?: string }) }
        },
      })

      editor.add({
        name: "security_dashboard",
        description: dashboardToolDef.description,
        input: {
          type: "object",
          properties: {
            mode: {
              type: "string",
              enum: ["full", "brief"],
              description: 'Display mode: "full" (default) or "brief" (one-line status)',
            },
          },
          additionalProperties: false,
        },
        async execute(input) {
          return { content: await dashboardToolDef.execute(input as { mode?: "full" | "brief" }) }
        },
      })

      editor.add({
        name: "security_report",
        description: reportToolDef.description,
        input: {
          type: "object",
          properties: {
            format: {
              type: "string",
              enum: ["summary", "detailed"],
              description: 'Report format: "summary" (default) or "detailed" (includes full timeline)',
            },
          },
          additionalProperties: false,
        },
        async execute(input) {
          return { content: await reportToolDef.execute(input as { format?: "summary" | "detailed" }) }
        },
      })

      editor.add({
        name: "security_audit",
        description: auditToolDef.description,
        input: {
          type: "object",
          properties: {
            tool: { type: "string", description: "Filter by tool name" },
            eventType: {
              type: "string",
              enum: ["block", "detection", "pass", "safety-block", "safety-warn"],
              description: "Filter by event type",
            },
            category: { type: "string", description: "Filter by detection category" },
            limit: { type: "number", description: "Max entries to return (default 20)" },
          },
          additionalProperties: false,
        },
        async execute(input) {
          return {
            content: await auditToolDef.execute(
              input as {
                tool?: string
                eventType?: "block" | "detection" | "pass" | "safety-block" | "safety-warn"
                category?: string
                limit?: number
              },
            ),
          }
        },
      })

      editor.add({
        name: "security_evaluate",
        description: evaluateToolDef.description,
        input: {
          type: "object",
          properties: {
            tool: { type: "string", description: 'Tool name to evaluate (e.g., "bash", "write", "edit")' },
            command: { type: "string", description: "Command string (for bash tool)" },
            args: { type: "string", description: "JSON string of tool arguments (for non-bash tools)" },
          },
          required: ["tool"],
          additionalProperties: false,
        },
        async execute(input) {
          return {
            content: await evaluateToolDef.execute(input as { tool: string; command?: string; args?: string }),
          }
        },
      })

      editor.add({
        name: "security_config",
        description: configToolDef.description,
        input: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
        async execute() {
          return { content: await configToolDef.execute() }
        },
      })

      editor.add({
        name: "security_rules",
        description: rulesToolDef.description,
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["list", "test", "add", "edit", "remove"],
              description: 'Action: "list", "test", "add", "edit", or "remove"',
            },
            pattern: { type: "string", description: "Regex pattern (for test/add/edit)" },
            testString: { type: "string", description: "Sample string to test against" },
            name: { type: "string", description: "Rule name (for add/edit)" },
            category: { type: "string", description: "Category (for add/edit)" },
            id: { type: "string", description: "Rule ID (for edit/remove)" },
            redactTemplate: { type: "string", description: "Redaction replacement text" },
          },
          required: ["action"],
          additionalProperties: false,
        },
        async execute(input) {
          return {
            content: await rulesToolDef.execute(
              input as {
                action: "list" | "test" | "add" | "edit" | "remove"
                pattern?: string
                testString?: string
                name?: string
                category?: string
                id?: string
                redactTemplate?: string
              },
            ),
          }
        },
      })

      // Enforce blockedTools on the actual registered surface. Removal uses the
      // editor's effective id (namespace-aware), not the configured spelling.
      const removedTools = removeBlockedTransformTools(editor, config)
      if (removedTools.length > 0) {
        diagnosticLogger?.info(
          `Tool surface: removed ${removedTools.length} blocked tool(s): ${removedTools.join(", ")}`,
        )
      }
    })

      // ─── Cleanup ───
      return () => {
        disposeResources?.()
        void bridge.dispose()
      }
    } catch {
      // Any unexpected setup exception must never leave the host running with
      // no Warden hooks. OpenCode drops a plugin whose setup throws, so install
      // the deny-all lockdown instead and keep the exception text out of logs
      // (it could contain configured values).
      notificationsEnabled = false
      try {
        disposeResources?.()
      } catch {
        /* cleanup failure is non-critical */
      }
      try {
        await notificationBridge?.dispose()
      } catch {
        /* notification failure is non-critical */
      }
      try {
        await registerFailClosedHooks(ctx, {
          source: "setup",
          code: "WARDEN_SETUP_FAILURE",
          message: "unexpected setup failure",
        })
      } catch {
        // Nothing further can be installed; the host will surface setup failure.
      }
      return () => {}
    }
  },
})
