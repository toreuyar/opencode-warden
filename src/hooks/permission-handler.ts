import type { SafetyEvaluator } from "../llm/safety-evaluator.js"
import { requestFailureMessage } from "../llm/request-context.js"
import type { AuditLogger } from "../audit/index.js"
import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type {
  PermissionDecision,
  PermissionInput,
  SafetyEvaluationResult,
  SecurityGuardConfig,
  PluginClient,
} from "../types.js"
import { isRemoteCommand } from "../utils/ssh.js"
import { isAbsolute, resolve } from "path"
import {
  isAllowlisted,
  isPathBlockedForMode,
  extractFileTargets,
  extractRemoteFilePathsFromArgs,
} from "../utils/paths.js"
import { canonicalToolName, isToolInList } from "../utils/tool-compat.js"
import { hasSequentialShellBatch, SHELL_SEQUENCE_BLOCK_MESSAGE, SHELL_SEQUENCE_BLOCK_REASON } from "../utils/shell-sequence.js"

export type { PermissionDecision, PermissionInput } from "../types.js"

interface PermissionHandlerDeps {
  config: SecurityGuardConfig
  client: PluginClient
  projectDir?: string
  safetyEvaluator?: SafetyEvaluator | null
  evaluatedCalls?: Set<string>
  sessionAllowlist?: Set<string>
  auditLogger: AuditLogger
  diagnosticLogger: DiagnosticLogger | null
  getSessionState?: (sessionID: string) => {
    safetyEvaluator: SafetyEvaluator | null
    evaluatedCalls: Set<string>
    sessionAllowlist: Set<string>
  }
}

function permissionAction(input: PermissionInput): string {
  return input.action ?? input.type ?? input.permission ?? ""
}

function permissionResources(input: PermissionInput): string[] {
  if (Array.isArray(input.resources)) return input.resources
  if (Array.isArray(input.patterns)) return input.patterns
  if (Array.isArray(input.pattern)) return input.pattern
  if (typeof input.pattern === "string") return [input.pattern]
  return []
}

function permissionCallID(input: PermissionInput): string | undefined {
  return input.callID ?? input.tool?.callID ?? input.tool?.id
}

function permissionTitle(input: PermissionInput, metadata: Record<string, unknown>): string {
  if (typeof input.title === "string" && input.title.length > 0) return input.title
  if (typeof input.message === "string" && input.message.length > 0) return input.message
  return typeof metadata.command === "string" ? metadata.command : ""
}

export function createPermissionHandler(deps: PermissionHandlerDeps) {
  const {
    config,
    client,
    projectDir,
    auditLogger,
    diagnosticLogger,
    getSessionState,
  } = deps

  const getState = (sessionID: string) => {
    if (getSessionState) return getSessionState(sessionID)
    if (!deps.evaluatedCalls || !deps.sessionAllowlist) {
      throw new Error("Warden: permission handler session state is not configured")
    }
    return {
      safetyEvaluator: deps.safetyEvaluator ?? null,
      evaluatedCalls: deps.evaluatedCalls,
      sessionAllowlist: deps.sessionAllowlist,
    }
  }

  const debugLog = config.llm.debug
    ? (msg: string) => {
        client.app.log({
          body: { service: "warden", level: "info", message: msg },
        }).catch(() => {})
      }
    : undefined

  return async (
    input: PermissionInput,
    output: PermissionDecision,
  ) => {
    const hookStart = Date.now()
    const { safetyEvaluator, evaluatedCalls, sessionAllowlist } = getState(input.sessionID)
    const action = permissionAction(input)
    const canonicalAction = canonicalToolName(action)
    const metadata = input.metadata ?? {}
    const resources = permissionResources(input)
    const callID = permissionCallID(input)
    const title = permissionTitle(input, metadata)

    diagnosticLogger?.hookStart("permission-handler", action, callID ?? input.id, input.sessionID, {
      title,
      status: output.status,
    })

    // Entry-point log — this fires for EVERY permission.ask invocation
    debugLog?.(
      `Permission hook INVOKED: action=${action} id=${input.id} callID=${callID ?? "none"} sessionID=${input.sessionID} status=${output.status} resources=${JSON.stringify(resources)} title="${title}"`,
    )

    const safetyActionMode = config.llm.safetyEvaluator.actionMode

    // Only act in "permission" mode
    if (safetyActionMode !== "permission") {
      debugLog?.(`Permission hook: actionMode=${safetyActionMode} → SKIPPED (not permission mode)`)
      diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "skipped", reason: `actionMode=${safetyActionMode}` })
      return
    }

    // SSH-only mode: skip non-remote commands. Alias-aware: V2 `shell` and
    // legacy `bash` are the same policy action.
    if (config.sshOnlyMode) {
      if (canonicalAction === "shell") {
        const args = { ...metadata } as Record<string, unknown>
        if (!args.command) {
          const resourceCommand = resources.find(
            (resource): resource is string => typeof resource === "string" && resource.length > 0,
          )
          if (resourceCommand) args.command = resourceCommand
        }
        if (!args.command && title) {
          args.command = title
        }
        const command = typeof args.command === "string" ? args.command : ""
        if (!isRemoteCommand(command)) {
          debugLog?.(`Permission hook: action=${action} → SKIPPED (sshOnlyMode: not a remote command)`)
          diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "skipped", reason: "sshOnlyMode: not a remote command" })
          return
        }
      } else {
        debugLog?.(`Permission hook: action=${action} → SKIPPED (sshOnlyMode: non-shell action)`)
        diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "skipped", reason: "sshOnlyMode: non-shell action" })
        return
      }
    }

    // Build args from metadata and V2 permission resources for safety
    // evaluation. For `shell`, resources are the RAW COMMAND string, never
    // paths. For file actions, resources are relative paths.
    const args = { ...metadata } as Record<string, unknown>
    const resourceCommands =
      canonicalAction === "shell"
        ? resources.filter((resource): resource is string => typeof resource === "string" && resource.length > 0)
        : []
    if (canonicalAction === "shell" && typeof args.command !== "string") {
      if (resourceCommands.length > 0) {
        args.command = resourceCommands[0]
      } else if (title) {
        args.command = title
      }
    }
    if (resources.length > 0 && args.resources === undefined) {
      args.resources = resources
    }

    // ─── Deterministic checks (before LLM evaluation and before any
    // evaluator-eligibility gate) ───
    // These must run before LLM safety evaluation so that deterministic
    // blocks produce accurate messages. They must also run before
    // `shouldEvaluate()`: a blocked tool or file must be denied even when it
    // is not in the evaluator's tool list, and even when the LLM is disabled.
    // Without this, a call that would be blocked by deterministic policy
    // depends on LLM configuration/availability to be denied.

    // Check blockedTools (alias-aware: blocked `subagent` also blocks `task`)
    if (isToolInList(action, config.blockedTools)) {
      debugLog?.(`Permission hook: action=${action} → DENIED (blockedTools)`)
      diagnosticLogger?.decision("permission-handler", action, `DENIED by blockedTools policy`)
      output.status = "deny"
      output.message = `Warden: Tool "${action}" is blocked by security policy. This tool has been disabled by the administrator.`

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: action,
        hook: "permission",
        sessionId: input.sessionID,
        callId: callID ?? input.id,
        detections: [],
        blocked: true,
        blockReason: `Tool "${action}" is blocked by security policy`,
        redactedCount: 0,
      })

      if (config.notifications) {
        try {
          await client.tui.showToast({
            body: {
              message: `🛡 Denied: tool "${action}" is not allowed`,
              variant: "error" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }

      try {
        await client.session.prompt({
          path: { id: input.sessionID },
          body: {
            noReply: true,
            parts: [{
              type: "text",
              text: `Warden: Tool "${action}" is blocked by security policy. This tool has been disabled by the administrator.`,
            }],
          },
        })
      } catch { /* session prompt injection is non-critical */ }

      diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "deny", reason: "blockedTools" })
      return
    }

    if (
      canonicalAction === "shell" &&
      !isToolInList(action, config.excludedTools) &&
      [args.command, ...resourceCommands].some((command) => hasSequentialShellBatch(action, command))
    ) {
      output.status = "deny"
      output.message = SHELL_SEQUENCE_BLOCK_MESSAGE
      diagnosticLogger?.decision("permission-handler", action, SHELL_SEQUENCE_BLOCK_REASON)
      try {
        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: action,
          hook: "permission",
          sessionId: input.sessionID,
          callId: callID ?? input.id,
          detections: [],
          blocked: true,
          blockReason: SHELL_SEQUENCE_BLOCK_REASON,
          redactedCount: 0,
        })
      } catch { /* audit failure is non-critical */ }
      if (config.notifications) {
        try {
          await client.tui.showToast({
            body: { message: `🛡 Denied: ${SHELL_SEQUENCE_BLOCK_REASON}`, variant: "error" as const },
          })
        } catch { /* toast failure is non-critical */ }
      }
      diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "deny", reason: SHELL_SEQUENCE_BLOCK_REASON })
      return
    }

    // Check every local file target (mode-aware: writes also honor
    // writeProtectedPaths). Uses the shared multi-target extractor so V2
    // `path`, legacy `filePath`, all patch targets including moves, and shell
    // redirection/read targets are covered. V2 permission `resources` are also
    // treated as targets; the action decides their default mode.
    const denyLocalTarget = async (targetPath: string, accessMode: "read" | "write"): Promise<boolean> => {
      if (isAllowlisted(targetPath, sessionAllowlist, projectDir)) return false
      if (!isPathBlockedForMode(targetPath, accessMode, config.blockedFilePaths, config.writeProtectedPaths, config.whitelistedPaths, projectDir)) return false

      debugLog?.(`Permission hook: action=${action} → DENIED (blocked file path (${accessMode}): ${targetPath})`)
      diagnosticLogger?.decision("permission-handler", action, `DENIED file path (${accessMode}): ${targetPath}`)
      output.status = "deny"
      output.message = `Warden: Access to "${targetPath}" is blocked by security policy. This file may contain sensitive data. If you need access, ask the user to temporarily allowlist it.`

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: action,
        hook: "permission",
        sessionId: input.sessionID,
        callId: callID ?? input.id,
        detections: [],
        blocked: true,
        blockReason: `Blocked file path (${accessMode}): ${targetPath}`,
        redactedCount: 0,
      })

      if (config.notifications) {
        try {
          await client.tui.showToast({
            body: {
              message: `🛡 Denied: ${targetPath} access denied`,
              variant: "error" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }

      try {
        await client.session.prompt({
          path: { id: input.sessionID },
          body: {
            noReply: true,
            parts: [{
              type: "text",
              text: output.message,
            }],
          },
        })
      } catch { /* session prompt injection is non-critical */ }

      diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "deny", reason: "blocked file path" })
      return true
    }

    const resourceMode: "read" | "write" =
      canonicalAction === "write" || canonicalAction === "edit" || canonicalAction === "patch"
        ? "write"
        : "read"

    // V2 permission resources are relative paths for file actions. Resolve
    // them against the session/workspace directory before glob matching so
    // deterministic policy does not depend on the process cwd.
    const resolveResourcePath = (resource: string): string => {
      if (!projectDir || isAbsolute(resource) || resource.startsWith("~/")) return resource
      return resolve(projectDir, resource)
    }

    const deterministicTargets = [...extractFileTargets(action, args)]
    const resourceIsFilePath =
      canonicalAction === "read" ||
      canonicalAction === "write" ||
      canonicalAction === "edit" ||
      canonicalAction === "patch" ||
      canonicalAction === "glob" ||
      canonicalAction === "grep"
    if (canonicalAction === "shell") {
      // For `shell`, resources[0] is the RAW COMMAND string, not a path.
      // Parse every command resource with the shell target helper.
      for (const command of resourceCommands) {
        deterministicTargets.push(...extractFileTargets("shell", { command }))
      }
    } else if (resourceIsFilePath) {
      // File-action resources are relative paths. Non-file actions (e.g.
      // `subagent` resources are agent IDs) must not be treated as paths.
      for (const resource of resources) {
        if (typeof resource !== "string" || resource.length === 0) continue
        deterministicTargets.push({ path: resolveResourcePath(resource), mode: resourceMode })
      }
    }

    const checkedTargets = new Set<string>()
    for (const target of deterministicTargets) {
      const key = `${target.mode}\u0000${target.path}`
      if (checkedTargets.has(key)) continue
      checkedTargets.add(key)
      if (await denyLocalTarget(target.path, target.mode)) return
    }

    // Check remote file paths (SSH/SCP/rsync/rclone) — mode-aware
    const remotePaths = extractRemoteFilePathsFromArgs(action, args)
    if (canonicalAction === "shell") {
      for (const command of resourceCommands) {
        remotePaths.push(...extractRemoteFilePathsFromArgs("shell", { command }))
      }
    }
    const checkedRemote = new Set<string>()
    for (const { path: remotePath, mode: remoteMode } of remotePaths) {
      const remoteKey = `${remoteMode}\u0000${remotePath}`
      if (checkedRemote.has(remoteKey)) continue
      checkedRemote.add(remoteKey)
      if (
        !isAllowlisted(remotePath, sessionAllowlist) &&
        isPathBlockedForMode(remotePath, remoteMode, config.blockedFilePaths, config.writeProtectedPaths, config.whitelistedPaths)
      ) {
        debugLog?.(`Permission hook: action=${action} → DENIED (blocked remote file path (${remoteMode}): ${remotePath})`)
        diagnosticLogger?.decision("permission-handler", action, `DENIED remote file path (${remoteMode}): ${remotePath}`)
        output.status = "deny"
        output.message = `Warden: Remote access to "${remotePath}" is blocked by security policy. This file may contain sensitive data. If you need access, ask the user to temporarily allowlist it.`

        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: action,
          hook: "permission",
          sessionId: input.sessionID,
          callId: callID ?? input.id,
          detections: [],
          blocked: true,
          blockReason: `Blocked remote file path: ${remotePath}`,
          redactedCount: 0,
        })

        if (config.notifications) {
          try {
            await client.tui.showToast({
              body: {
                message: `🛡 Denied: remote access to ${remotePath} denied`,
                variant: "error" as const,
              },
            })
          } catch { /* toast failure is non-critical */ }
        }

        try {
          await client.session.prompt({
            path: { id: input.sessionID },
            body: {
              noReply: true,
              parts: [{
                type: "text",
                text: output.message,
              }],
            },
          })
        } catch { /* session prompt injection is non-critical */ }

        diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "deny", reason: "blocked remote file path" })
        return
      }
    }

    // ─── End deterministic checks ───

    // Evaluator availability gate. This runs after deterministic policy so a
    // blocked tool/file is always denied for the deterministic reason, never
    // because of LLM tool eligibility or availability.
    if (!safetyEvaluator) {
      // If the LLM + safety component are enabled but the evaluator is null,
      // something went wrong — deny every permission action that reaches this
      // point, regardless of tool list or action mode. Explicitly disabled
      // components remain deterministic-only: no outage denial.
      if (config.llm.enabled && config.llm.safetyEvaluator.enabled) {
        debugLog?.(`Permission hook: safety evaluator is null but the safety component is enabled → DENY (fail-closed)`)
        output.status = "deny"
        output.message = "Warden: Permission denied — safety evaluator unavailable (fail-closed)."

        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: action,
          hook: "permission",
          sessionId: input.sessionID,
          callId: callID ?? input.id,
          detections: [],
          blocked: true,
          blockReason: "Safety evaluator unavailable — fail-closed deny",
          redactedCount: 0,
        })

        if (config.notifications) {
          try {
            await client.tui.showToast({
              body: {
                message: `🛡 Denied: Safety evaluator unavailable — blocking for safety`,
                variant: "error" as const,
              },
            })
          } catch { /* toast failure is non-critical */ }
        }

        diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "deny", reason: "safety evaluator unavailable" })
        return
      }

      debugLog?.(`Permission hook: no safety evaluator available (component disabled or LLM disabled) → SKIPPED`)
      diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "skipped", reason: "safety component disabled" })
      return
    }

    // Skip if tool is not in the evaluator's tool list (alias-aware)
    if (!safetyEvaluator.shouldEvaluate(action)) {
      debugLog?.(`Permission hook: action=${action} → SKIPPED (not in safety tools list)`)

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: action,
        hook: "permission",
        sessionId: input.sessionID,
        callId: callID ?? input.id,
        detections: [],
        blocked: false,
        blockReason: "Tool not in safety evaluator tool list — skipped",
        redactedCount: 0,
      })

      diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "skipped", reason: "tool not in safety list" })
      return
    }

    const precheck = canonicalAction === "shell" && !isToolInList(action, config.excludedTools) &&
      config.llm.enabled && config.llm.safetyEvaluator.complexityPrecheck?.enabled
      ? await safetyEvaluator.precheckComplexity(action, args)
      : undefined
    if (precheck && precheck !== "continue") {
      output.status = "deny"
      output.message = precheck.explanation
      try {
        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: action,
          hook: "permission",
          sessionId: input.sessionID,
          callId: callID ?? input.id,
          detections: [],
          blocked: true,
          blockReason: precheck.explanation,
          redactedCount: 0,
          safetyEvaluation: precheck,
        })
      } catch { /* audit failure is non-critical */ }
      if (config.notifications) {
        try {
          await client.tui.showToast({
            body: { message: `🛡 Denied: ${precheck.explanation}`, variant: "error" as const },
          })
        } catch { /* toast failure is non-critical */ }
      }
      diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "deny", reason: precheck.explanation })
      return
    }

    // A precheck continuation is not pre-approval.
    if (precheck !== "continue" && safetyEvaluator.isBypassed(action, args)) {
      debugLog?.(`Permission hook: action=${action} → BYPASSED → auto-allow`)
      diagnosticLogger?.decision("permission-handler", action, "BYPASSED → auto-allow")
      output.status = "allow"
      if (callID) evaluatedCalls.add(callID)

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: action,
        hook: "permission",
        sessionId: input.sessionID,
        callId: callID ?? input.id,
        detections: [],
        blocked: false,
        blockReason: "Bypassed by command pattern match — auto-allowed",
        redactedCount: 0,
      })

      if (config.notifications) {
        try {
          const cmdPreview = (args.command as string || title || action).substring(0, 60)
          await client.tui.showToast({
            body: {
              message: `Approved by ruleset: ${cmdPreview}`,
              variant: "info" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }

      diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "allow", reason: "bypassed" })
      return
    }

    debugLog?.(`Permission hook: action=${action} → evaluating safety...`)

    if (config.notifications) {
      try {
        const cmdPreview = (args.command as string || title || action).substring(0, 60)
        await client.tui.showToast({
          body: {
            message: `Escalated to LLM: ${cmdPreview}`,
            variant: "info" as const,
          },
        })
      } catch { /* toast failure is non-critical */ }
    }

    const safetyResult: SafetyEvaluationResult = await safetyEvaluator.evaluate(action, args)
    diagnosticLogger?.decision("permission-handler", action, `Safety eval: ${safetyResult.recommendation} (risk=${safetyResult.riskLevel}${safetyResult.evaluationFailed ? ", evaluationFailed" : ""})`, {
      safe: safetyResult.safe,
      riskLevel: safetyResult.riskLevel,
      recommendation: safetyResult.recommendation,
      riskDimensions: safetyResult.riskDimensions,
      evaluationFailed: safetyResult.evaluationFailed === true,
    })

    // An evaluator outage, timeout, misconfiguration, or garbage response must
    // deny regardless of actionMode. A genuine model "block" verdict is
    // handled below; this branch is only for an untrustworthy verdict.
    if (safetyResult.evaluationFailed) {
      output.status = "deny"
      output.message =
        safetyResult.requestFailure ? requestFailureMessage(safetyResult.requestFailure) :
        safetyResult.providerOverloaded
          ? "Warden: LLM provider overloaded by concurrent requests (queue full or wait timed out). Permission denied; retry later."
          :
        "Warden: Permission denied — safety evaluator unavailable (fail-closed). " +
        "The evaluator is unreachable, misconfigured, timed out, or returned an unusable response."

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: action,
        hook: "permission",
        sessionId: input.sessionID,
        callId: callID ?? input.id,
        detections: [],
        blocked: true,
        blockReason: "Safety evaluator unavailable — fail-closed deny",
        redactedCount: 0,
        safetyEvaluation: safetyResult,
      })

      if (config.notifications) {
        try {
          await client.tui.showToast({
            body: {
              message: `🛡 Denied: Safety evaluator unavailable — blocking for safety`,
              variant: "error" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }

      // Do NOT mark the call as evaluated: the call must remain blocked, and a
      // failed evaluation must never let a later hook skip re-evaluation.
      debugLog?.(`Permission hook: action=${action} → DENIED (evaluator unavailable)`)
      diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "deny", reason: "evaluationFailed" })
      return
    }

    if (safetyResult.recommendation === "block") {
      // Critical risk: auto-deny, user doesn't get a choice
      output.status = "deny"

      const suggestion = safetyResult.suggestedAlternative
        ? `\nGuidance: ${safetyResult.suggestedAlternative}`
        : ""
      const denialText =
        `Warden: Command denied (${safetyResult.riskLevel} risk).\n` +
        `Reason: ${safetyResult.explanation}` +
        suggestion
      // V2 PermissionEvaluation supports a message field; v2-adapters.ts
      // forwards it onto event.message.
      output.message = denialText

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: action,
        hook: "permission",
        sessionId: input.sessionID,
        callId: callID ?? input.id,
        detections: [],
        blocked: true,
        blockReason: `Safety evaluation: ${safetyResult.explanation}`,
        redactedCount: 0,
        safetyEvaluation: safetyResult,
      })

      if (config.notifications) {
        try {
          await client.tui.showToast({
            body: {
              message: `🛡 Denied: ${safetyResult.explanation.substring(0, 100)}`,
              variant: "error" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }

      // Inject guidance into the main LLM's session context
      try {
        await client.session.prompt({
          path: { id: input.sessionID },
          body: {
            noReply: true,
            parts: [{
              type: "text",
              text: denialText,
            }],
          },
        })
      } catch { /* session prompt injection is non-critical */ }

      // A denied call is not marked evaluated: if execution somehow reaches
      // the input sanitizer anyway, it must evaluate rather than skip.
      debugLog?.(`Permission hook: action=${action} → DENIED (risk=${safetyResult.riskLevel})`)
      diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "deny", riskLevel: safetyResult.riskLevel })
      return
    }

    if (safetyResult.recommendation === "warn") {
      // Medium/high risk: let user decide via OpenCode's permission prompt
      output.status = "ask"
      if (callID) evaluatedCalls.add(callID)

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: action,
        hook: "permission",
        sessionId: input.sessionID,
        callId: callID ?? input.id,
        detections: [],
        blocked: false,
        blockReason: "Prompted user for permission (warn-level risk)",
        redactedCount: 0,
        safetyEvaluation: safetyResult,
      })

      if (config.notifications) {
        try {
          await client.tui.showToast({
            body: {
              message: `⚠️ Risk detected (${safetyResult.riskLevel}): ${safetyResult.explanation.substring(0, 80)}`,
              variant: "warning" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }

      debugLog?.(`Permission hook: action=${action} → ASK user (risk=${safetyResult.riskLevel})`)
      diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "ask", riskLevel: safetyResult.riskLevel })
      return
    }

    // Safe: actively allow to bypass OpenCode's default "ask" behavior
    output.status = "allow"
    if (callID) evaluatedCalls.add(callID)
    debugLog?.(`Permission hook: action=${action} → SAFE → auto-allow (risk=${safetyResult.riskLevel})`)
    await auditLogger.log({
      timestamp: new Date().toISOString(),
      tool: action,
      hook: "permission",
      sessionId: input.sessionID,
      callId: callID ?? input.id,
      detections: [],
      blocked: false,
      redactedCount: 0,
      safetyEvaluation: safetyResult,
    })

    if (config.notifications) {
      try {
        const cmdPreview = (args.command as string || title || action).substring(0, 60)
        await client.tui.showToast({
          body: {
            message: `Approved by LLM (risk: ${safetyResult.riskLevel}): ${cmdPreview}`,
            variant: "success" as const,
          },
        })
      } catch { /* toast failure is non-critical */ }
    }

    diagnosticLogger?.hookEnd("permission-handler", action, callID ?? input.id, Date.now() - hookStart, { outcome: "allow", riskLevel: safetyResult.riskLevel })
  }
}
