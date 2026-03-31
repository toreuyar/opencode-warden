import type { Plugin } from "@opencode-ai/plugin"
import { tool } from "@opencode-ai/plugin"
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
import { buildSecurityPolicyContext } from "./hooks/security-policy.js"
import { createSecurityDashboardTool } from "./tools/security-dashboard.js"
import { createSecurityReportTool } from "./tools/security-report.js"
import { createRulesManageTool } from "./tools/rules-manage.js"
import type { ToastState, PatternCategory, PluginClient, WrittenFileMetadata } from "./types.js"

export const SecurityGuard: Plugin = async ({ client: sdkClient, directory }) => {
  // Cast SDK client to our PluginClient interface
  const client = sdkClient as unknown as PluginClient

  // ─── Load Configuration ───
  const { config, warnings: configWarnings } = loadConfig(directory)
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

  // ─── Create Session Stats ───
  const sessionStats = new SessionStats()

  // ─── Create LLM Components (if enabled) ───
  let llmSanitizer: LlmSanitizer | null = null
  let safetyEvaluator: SafetyEvaluator | null = null
  let outputTriage: OutputTriageEvaluator | null = null
  let outputTextTriage: OutputTextTriageEvaluator | null = null

  if (config.llm.enabled) {
    // Panel-based debug log (existing behavior)
    const panelDebugLog = config.llm.debug
      ? (msg: string) => {
          client.app.log({
            body: { service: "security-guard", level: "info", message: msg },
          }).catch(() => {})
        }
      : undefined

    // File-based debug log for diagnostic file
    const fileDebugLog = diagnosticLogger
      ? (msg: string) => diagnosticLogger!.info(msg)
      : undefined

    // Combined: call both if either exists
    const debugLog = (panelDebugLog || fileDebugLog)
      ? (msg: string) => { panelDebugLog?.(msg); fileDebugLog?.(msg) }
      : undefined

    // Build ProviderChain instances from resolved config
    // Each component uses its own providers (already resolved by config inheritance)
    const sanitizerChain = new ProviderChain(config.llm.outputSanitizer.providers, debugLog, llmChatLogger)
    const safetyChain = new ProviderChain(config.llm.safetyEvaluator.providers, debugLog, llmChatLogger)

    llmSanitizer = new LlmSanitizer(config.llm, sanitizerChain, debugLog)
    safetyEvaluator = new SafetyEvaluator(config.llm, safetyChain, debugLog, config.indirectExecution)

    if (config.llm.outputTriage.enabled) {
      const triageChain = new ProviderChain(config.llm.outputTriage.providers, debugLog, llmChatLogger)
      outputTriage = new OutputTriageEvaluator(config.llm.outputTriage, triageChain, debugLog)
    }

    if (config.llm.outputTextTriage.enabled) {
      const textTriageChain = new ProviderChain(config.llm.outputTextTriage.providers, debugLog, llmChatLogger)
      outputTextTriage = new OutputTextTriageEvaluator(config.llm.outputTextTriage, textTriageChain, debugLog)
    }

    // Health check (non-blocking — don't block plugin startup)
    llmSanitizer.healthCheck().then((healthy) => {
      if (!healthy) {
        client.app.log({
          body: {
            service: "security-guard",
            level: "error",
            message:
              "LLM unreachable — all LLM-evaluated operations will be BLOCKED until LLM is available",
          },
        }).catch(() => {})

        if (config.notifications) {
          client.tui.showToast({
            body: {
              message: "🛡 Security Guard: LLM unreachable — LLM-evaluated operations will be BLOCKED",
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

  // ─── Shared State ───
  const toastState: ToastState = {
    lastToastTime: 0,
    minInterval: 2000, // Max 1 toast per 2 seconds
  }
  const sessionAllowlist = new Set<string>()
  const evaluatedCalls = new Set<string>()
  const writtenFileRegistry = new Map<string, WrittenFileMetadata>()
  let policyInjected = false
  const securityPolicyText = buildSecurityPolicyContext(config)

  // ─── Create Hooks ───
  const inputSanitizer = createInputSanitizer({
    engine,
    config,
    auditLogger,
    sessionStats,
    client,
    safetyEvaluator,
    toastState,
    sessionAllowlist,
    evaluatedCalls,
    diagnosticLogger,
    writtenFileRegistry,
  })

  const outputRedactor = createOutputRedactor({
    engine,
    config,
    auditLogger,
    sessionStats,
    client,
    llmSanitizer,
    outputTriage,
    outputTextTriage,
    toastState,
    diagnosticLogger,
  })

  const envSanitizer = createEnvSanitizer({
    engine,
    config,
    auditLogger,
    sessionStats,
    client,
    toastState,
    diagnosticLogger,
  })

  const compactionContext = createCompactionContext({ config, diagnosticLogger })

  const permissionHandler = createPermissionHandler({
    config,
    client,
    safetyEvaluator,
    evaluatedCalls,
    auditLogger,
    diagnosticLogger,
  })

  // ─── Create Custom Tools ───
  const dashboardToolDef = createSecurityDashboardTool({
    sessionStats,
    config,
    llmSanitizer,
  })

  const reportToolDef = createSecurityReportTool({ sessionStats })

  const rulesToolDef = createRulesManageTool({
    engine,
    config,
    projectDir: directory,
  })

  // ─── Log Startup ───
  const activeCategories = (
    Object.entries(config.categories) as [PatternCategory, boolean][]
  )
    .filter(([, enabled]) => enabled)
    .map(([cat]) => cat)

  const patternCount = engine.getPatterns().length

  client.app.log({
    body: {
      service: "security-guard",
      level: "info",
      message: `Security Guard active: ${patternCount} patterns, ${activeCategories.length} categories [${activeCategories.join(", ")}], LLM: ${config.llm.enabled ? "enabled" : "disabled"}`,
    },
  }).catch(() => {})

  diagnosticLogger?.startup(
    `Security Guard active: ${patternCount} patterns, ${activeCategories.length} categories, LLM: ${config.llm.enabled ? "enabled" : "disabled"}`,
    {
      categories: activeCategories,
      patternCount,
      llmEnabled: config.llm.enabled,
      diagnosticLog: config.diagnosticLog.filePath,
    },
  )

  // ─── Show Startup Warnings ───
  for (const warning of startupWarnings) {
    client.app.log({
      body: { service: "security-guard", level: "warn", message: warning },
    }).catch(() => {})
    if (config.notifications) {
      client.tui.showToast({
        body: { message: `Config: ${warning}`, variant: "warning" as const },
      }).catch(() => {})
    }
  }

  // ─── Return Plugin Hooks & Tools ───
  return {
    "tool.execute.before": async (
      input: { tool: string; sessionID: string; callID: string },
      output: { args: Record<string, unknown> },
    ) => {
      // Inject security policy into session on first tool call
      if (!policyInjected && input.sessionID) {
        policyInjected = true
        try {
          await client.session.prompt({
            path: { id: input.sessionID },
            body: {
              noReply: true,
              parts: [{ type: "text", text: securityPolicyText }],
            },
          })
        } catch {
          // Non-critical — compaction context is the fallback
        }
      }
      return inputSanitizer(input, output)
    },
    "tool.execute.after": outputRedactor,
    "permission.ask": permissionHandler,
    "shell.env": envSanitizer,
    "experimental.session.compacting": compactionContext,

    event: async ({ event }) => {
      if (event.type === "session.created") {
        diagnosticLogger?.info("Session reset: clearing all state")
        sessionStats.reset("")
        sessionAllowlist.clear()
        evaluatedCalls.clear()
        writtenFileRegistry.clear()
        policyInjected = false
        llmSanitizer?.reset()
        safetyEvaluator?.reset()
      }
    },

    tool: {
      security_dashboard: tool({
        description: dashboardToolDef.description,
        args: {},
        async execute() {
          return dashboardToolDef.execute()
        },
      }),

      security_report: tool({
        description: reportToolDef.description,
        args: {
          format: tool.schema
            .enum(["summary", "detailed"])
            .optional()
            .describe(
              'Report format: "summary" (default) or "detailed" (includes full timeline)',
            ),
        },
        async execute(args) {
          return reportToolDef.execute(args)
        },
      }),

      security_rules: tool({
        description: rulesToolDef.description,
        args: {
          action: tool.schema
            .enum(["list", "test", "add", "remove"])
            .describe('Action: "list", "test", "add", or "remove"'),
          pattern: tool.schema
            .string()
            .optional()
            .describe("Regex pattern (for test/add)"),
          testString: tool.schema
            .string()
            .optional()
            .describe("Sample string to test against"),
          name: tool.schema
            .string()
            .optional()
            .describe("Rule name (for add)"),
          category: tool.schema
            .string()
            .optional()
            .describe("Category (for add)"),
          id: tool.schema
            .string()
            .optional()
            .describe("Rule ID (for remove)"),
          redactTemplate: tool.schema
            .string()
            .optional()
            .describe("Redaction replacement text"),
        },
        async execute(args) {
          return rulesToolDef.execute(args)
        },
      }),
    },
  }
}

export default SecurityGuard
