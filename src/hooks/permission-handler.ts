import type { SafetyEvaluator } from "../llm/safety-evaluator.js"
import type { AuditLogger } from "../audit/index.js"
import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type {
  SecurityGuardConfig,
  PluginClient,
} from "../types.js"
import { isRemoteCommand } from "../utils/ssh.js"

interface PermissionInput {
  id: string
  type: string
  pattern?: string | Array<string>
  sessionID: string
  messageID: string
  callID?: string
  title: string
  metadata: Record<string, unknown>
  time: { created: number }
}

interface PermissionHandlerDeps {
  config: SecurityGuardConfig
  client: PluginClient
  safetyEvaluator: SafetyEvaluator | null
  evaluatedCalls: Set<string>
  auditLogger: AuditLogger
  diagnosticLogger: DiagnosticLogger | null
}

export function createPermissionHandler(deps: PermissionHandlerDeps) {
  const {
    config,
    client,
    safetyEvaluator,
    evaluatedCalls,
    auditLogger,
    diagnosticLogger,
  } = deps

  const debugLog = config.llm.debug
    ? (msg: string) => {
        client.app.log({
          body: { service: "security-guard", level: "info", message: msg },
        }).catch(() => {})
      }
    : undefined

  return async (
    input: PermissionInput,
    output: { status: "ask" | "deny" | "allow" },
  ) => {
    const hookStart = Date.now()
    diagnosticLogger?.hookStart("permission-handler", input.type, input.callID ?? input.id, input.sessionID, {
      title: input.title,
      status: output.status,
    })

    // Entry-point log — this fires for EVERY permission.ask invocation
    debugLog?.(
      `Permission hook INVOKED: type=${input.type} id=${input.id} callID=${input.callID ?? "none"} sessionID=${input.sessionID} status=${output.status} pattern=${JSON.stringify(input.pattern)} title="${input.title}"`,
    )

    const safetyActionMode = config.llm.safetyEvaluator.actionMode

    // Only act in "permission" mode
    if (safetyActionMode !== "permission") {
      debugLog?.(`Permission hook: actionMode=${safetyActionMode} → SKIPPED (not permission mode)`)
      diagnosticLogger?.hookEnd("permission-handler", input.type, input.callID ?? input.id, Date.now() - hookStart, { outcome: "skipped", reason: `actionMode=${safetyActionMode}` })
      return
    }

    // SSH-only mode: skip non-remote commands
    if (config.sshOnlyMode) {
      const toolName = input.type
      if (toolName === "bash") {
        const args = { ...(input.metadata || {}) } as Record<string, unknown>
        if (!args.command && input.title) {
          args.command = input.title
        }
        const command = typeof args.command === "string" ? args.command : ""
        if (!isRemoteCommand(command)) {
          debugLog?.(`Permission hook: tool=${toolName} → SKIPPED (sshOnlyMode: not a remote command)`)
          diagnosticLogger?.hookEnd("permission-handler", toolName, input.callID ?? input.id, Date.now() - hookStart, { outcome: "skipped", reason: "sshOnlyMode: not a remote command" })
          return
        }
      } else {
        debugLog?.(`Permission hook: tool=${input.type} → SKIPPED (sshOnlyMode: non-bash tool)`)
        diagnosticLogger?.hookEnd("permission-handler", input.type, input.callID ?? input.id, Date.now() - hookStart, { outcome: "skipped", reason: "sshOnlyMode: non-bash tool" })
        return
      }
    }

    if (!safetyEvaluator) {
      // If LLM + safety evaluator is enabled in config but evaluator is null,
      // something went wrong — fail closed by denying
      if (config.llm.enabled && config.llm.safetyEvaluator.enabled) {
        debugLog?.(`Permission hook: safety evaluator is null but LLM is enabled → DENY (fail-closed)`)
        output.status = "deny"

        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: input.type,
          hook: "permission",
          sessionId: input.sessionID,
          callId: input.callID ?? input.id,
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
        return
      }

      debugLog?.(`Permission hook: no safety evaluator available → SKIPPED`)
      return
    }

    // Extract tool name from permission type
    const toolName = input.type
    const callID = input.callID

    // Skip if tool is not in the evaluator's tool list
    if (!safetyEvaluator.shouldEvaluate(toolName)) {
      debugLog?.(`Permission hook: tool=${toolName} → SKIPPED (not in safety tools list)`)

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: toolName,
        hook: "permission",
        sessionId: input.sessionID,
        callId: callID ?? input.id,
        detections: [],
        blocked: false,
        blockReason: "Tool not in safety evaluator tool list — skipped",
        redactedCount: 0,
      })

      return
    }

    // Build args from metadata for safety evaluation
    // For bash tools, the command may be in metadata.command or derivable from title/pattern
    const args = { ...(input.metadata || {}) } as Record<string, unknown>
    if (toolName === "bash" && !args.command && input.title) {
      args.command = input.title
    }

    // Check bypass list
    if (safetyEvaluator.isBypassed(toolName, args)) {
      debugLog?.(`Permission hook: tool=${toolName} → BYPASSED → auto-allow`)
      diagnosticLogger?.decision("permission-handler", toolName, "BYPASSED → auto-allow")
      output.status = "allow"
      if (callID) evaluatedCalls.add(callID)

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: toolName,
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
          const cmdPreview = (args.command as string || input.title || toolName).substring(0, 60)
          await client.tui.showToast({
            body: {
              message: `Approved by ruleset: ${cmdPreview}`,
              variant: "info" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }

      diagnosticLogger?.hookEnd("permission-handler", toolName, input.callID ?? input.id, Date.now() - hookStart, { outcome: "allow", reason: "bypassed" })
      return
    }

    debugLog?.(`Permission hook: tool=${toolName} → evaluating safety...`)

    if (config.notifications) {
      try {
        const cmdPreview = (args.command as string || input.title || toolName).substring(0, 60)
        await client.tui.showToast({
          body: {
            message: `Escalated to LLM: ${cmdPreview}`,
            variant: "info" as const,
          },
        })
      } catch { /* toast failure is non-critical */ }
    }

    const safetyResult = await safetyEvaluator.evaluate(toolName, args)
    diagnosticLogger?.decision("permission-handler", toolName, `Safety eval: ${safetyResult.recommendation} (risk=${safetyResult.riskLevel})`, {
      safe: safetyResult.safe,
      riskLevel: safetyResult.riskLevel,
      recommendation: safetyResult.recommendation,
      riskDimensions: safetyResult.riskDimensions,
    })

    // Mark this call as evaluated so input-sanitizer skips re-evaluation
    if (callID) {
      evaluatedCalls.add(callID)
    }

    if (safetyResult.recommendation === "block") {
      // Critical risk: auto-deny, user doesn't get a choice
      output.status = "deny"

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: toolName,
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
        const suggestion = safetyResult.suggestedAlternative
          ? `\nGuidance: ${safetyResult.suggestedAlternative}`
          : ""
        await client.session.prompt({
          path: { id: input.sessionID },
          body: {
            noReply: true,
            parts: [{
              type: "text",
              text: `Security Guard: Command denied (${safetyResult.riskLevel} risk).\n` +
                    `Reason: ${safetyResult.explanation}` +
                    suggestion,
            }],
          },
        })
      } catch { /* session prompt injection is non-critical */ }

      debugLog?.(`Permission hook: tool=${toolName} → DENIED (risk=${safetyResult.riskLevel})`)
      diagnosticLogger?.hookEnd("permission-handler", toolName, input.callID ?? input.id, Date.now() - hookStart, { outcome: "deny", riskLevel: safetyResult.riskLevel })
      return
    }

    if (safetyResult.recommendation === "warn") {
      // Medium/high risk: let user decide via OpenCode's permission prompt
      output.status = "ask"

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: toolName,
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

      debugLog?.(`Permission hook: tool=${toolName} → ASK user (risk=${safetyResult.riskLevel})`)
      diagnosticLogger?.hookEnd("permission-handler", toolName, input.callID ?? input.id, Date.now() - hookStart, { outcome: "ask", riskLevel: safetyResult.riskLevel })
      return
    }

    // Safe: actively allow to bypass OpenCode's default "ask" behavior
    output.status = "allow"
    debugLog?.(`Permission hook: tool=${toolName} → SAFE → auto-allow (risk=${safetyResult.riskLevel})`)
    await auditLogger.log({
      timestamp: new Date().toISOString(),
      tool: toolName,
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
        const cmdPreview = (args.command as string || input.title || toolName).substring(0, 60)
        await client.tui.showToast({
          body: {
            message: `Approved by LLM (risk: ${safetyResult.riskLevel}): ${cmdPreview}`,
            variant: "success" as const,
          },
        })
      } catch { /* toast failure is non-critical */ }
    }

    diagnosticLogger?.hookEnd("permission-handler", toolName, input.callID ?? input.id, Date.now() - hookStart, { outcome: "allow", riskLevel: safetyResult.riskLevel })
  }
}
