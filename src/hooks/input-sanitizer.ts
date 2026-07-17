import type { DetectionEngine } from "../detection/engine.js"
import type { AuditLogger } from "../audit/index.js"
import type { SessionStats } from "../audit/session-stats.js"
import type { SafetyEvaluator } from "../llm/safety-evaluator.js"
import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type {
  SecurityGuardConfig,
  PluginClient,
  ToastState,
  PatternCategory,
  WrittenFileMetadata,
} from "../types.js"
import { isAllowlisted, isPathBlockedForMode, extractFilePath, extractRemoteFilePathsFromArgs, extractBashFileTargets, isDynamicPathTarget } from "../utils/paths.js"
import { deepScan } from "../utils/deep-scan.js"
import {
  extractExecutedFilePaths,
  isSystemPath,
  isBinaryFile,
  readFileContent,
  hasExecutableExtension,
} from "../utils/script-detection.js"
import { isRemoteCommand } from "../utils/ssh.js"

interface InputSanitizerDeps {
  engine: DetectionEngine
  config: SecurityGuardConfig
  auditLogger: AuditLogger
  projectDir?: string
  sessionStats?: SessionStats
  client: PluginClient
  safetyEvaluator?: SafetyEvaluator | null
  toastState?: ToastState
  sessionAllowlist?: Set<string>
  evaluatedCalls?: Set<string>
  diagnosticLogger: DiagnosticLogger | null
  writtenFileRegistry?: Map<string, WrittenFileMetadata>
  getSessionState?: (sessionID: string) => {
    sessionStats: SessionStats
    safetyEvaluator: SafetyEvaluator | null
    toastState: ToastState
    sessionAllowlist: Set<string>
    evaluatedCalls: Set<string>
    writtenFileRegistry: Map<string, WrittenFileMetadata>
  }
}

function canToast(state: ToastState): boolean {
  const now = Date.now()
  if (now - state.lastToastTime < state.minInterval) return false
  state.lastToastTime = now
  return true
}

export function createInputSanitizer(deps: InputSanitizerDeps) {
  const {
    engine,
    config,
    auditLogger,
    projectDir,
    client,
    diagnosticLogger,
    getSessionState,
  } = deps

  const getState = (sessionID: string) => {
    if (getSessionState) return getSessionState(sessionID)
    if (
      !deps.sessionStats ||
      !deps.toastState ||
      !deps.sessionAllowlist ||
      !deps.evaluatedCalls ||
      !deps.writtenFileRegistry
    ) {
      throw new Error("Warden: input sanitizer session state is not configured")
    }
    return {
      sessionStats: deps.sessionStats,
      safetyEvaluator: deps.safetyEvaluator ?? null,
      toastState: deps.toastState,
      sessionAllowlist: deps.sessionAllowlist,
      evaluatedCalls: deps.evaluatedCalls,
      writtenFileRegistry: deps.writtenFileRegistry,
    }
  }

  return async (
    input: { tool: string; sessionID: string; callID: string },
    output: { args: Record<string, unknown> },
  ) => {
    const hookStart = Date.now()
    const {
      sessionStats,
      safetyEvaluator,
      toastState,
      sessionAllowlist,
      evaluatedCalls,
      writtenFileRegistry,
    } = getState(input.sessionID)

    diagnosticLogger?.hookStart("input-sanitizer", input.tool, input.callID, input.sessionID, { args: output.args })

    sessionStats.recordToolCall()

    const debugLog = config.llm.debug
      ? (msg: string) => {
          client.app.log({
            body: { service: "warden", level: "info", message: msg },
          }).catch(() => {})
        }
      : undefined

    // Block tools on the blocklist (e.g., "task" to prevent subagent spawning)
    if (config.blockedTools.includes(input.tool)) {
      debugLog?.(`Input hook: tool=${input.tool} → BLOCKED (blockedTools)`)
      diagnosticLogger?.decision("input-sanitizer", input.tool, `BLOCKED by blockedTools policy`)

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: input.tool,
        hook: "before",
        sessionId: input.sessionID,
        callId: input.callID,
        detections: [],
        blocked: true,
        blockReason: `Tool "${input.tool}" is blocked by security policy`,
        redactedCount: 0,
      })

      if (config.notifications && canToast(toastState)) {
        try {
          await client.tui.showToast({
            body: { message: `🛡 Blocked: tool "${input.tool}" is not allowed`, variant: "error" as const },
          })
        } catch { /* toast failure is non-critical */ }
      }

      throw new Error(
        `Warden: Tool "${input.tool}" is blocked by security policy. ` +
        `This tool has been disabled by the administrator.`,
      )
    }

    // Skip excluded tools
    if (config.excludedTools.includes(input.tool)) {
      debugLog?.(`Input hook: tool=${input.tool} → SKIPPED (excluded)`)
      diagnosticLogger?.hookEnd("input-sanitizer", input.tool, input.callID, Date.now() - hookStart, { outcome: "skipped", reason: "excluded tool" })
      return
    }

    // SSH-only mode: skip all non-remote commands
    if (config.sshOnlyMode) {
      if (input.tool === "bash") {
        const command = typeof output.args.command === "string" ? output.args.command : ""
        if (!isRemoteCommand(command)) {
          debugLog?.(`Input hook: tool=${input.tool} → SKIPPED (sshOnlyMode: not a remote command)`)
          diagnosticLogger?.hookEnd("input-sanitizer", input.tool, input.callID, Date.now() - hookStart, { outcome: "skipped", reason: "sshOnlyMode: not a remote command" })
          return
        }
      } else {
        debugLog?.(`Input hook: tool=${input.tool} → SKIPPED (sshOnlyMode: non-bash tool)`)
        diagnosticLogger?.hookEnd("input-sanitizer", input.tool, input.callID, Date.now() - hookStart, { outcome: "skipped", reason: "sshOnlyMode: non-bash tool" })
        return
      }
    }

    // Step 1: Check file path blocking (mode-aware: writes also honor writeProtectedPaths)
    const filePath = extractFilePath(input.tool, output.args)
    if (filePath) {
      const isAllowlistedPath = isAllowlisted(filePath, sessionAllowlist, projectDir)
      const accessMode: "read" | "write" = ["write", "edit", "patch"].includes(input.tool) ? "write" : "read"

      if (
        !isAllowlistedPath &&
        isPathBlockedForMode(filePath, accessMode, config.blockedFilePaths, config.writeProtectedPaths, config.whitelistedPaths, projectDir)
      ) {
        diagnosticLogger?.decision("input-sanitizer", input.tool, `BLOCKED file path (${accessMode}): ${filePath}`)
        sessionStats.recordBlock(input.tool, filePath, "Blocked file path")

        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: input.tool,
          hook: "before",
          sessionId: input.sessionID,
          callId: input.callID,
          detections: [],
          blocked: true,
          blockReason: `Blocked file path: ${filePath}`,
          redactedCount: 0,
        })

        if (config.notifications && canToast(toastState)) {
          try {
            await client.tui.showToast({
              body: { message: `🛡 Blocked: ${filePath} access denied`, variant: "error" as const },
            })
          } catch { /* toast failure is non-critical */ }
        }

        throw new Error(
          `Warden: Access to "${filePath}" is blocked by security policy. ` +
          `This file may contain sensitive data (credentials, keys, secrets). ` +
          `If you need access, ask the user to temporarily allowlist it.`,
        )
      }
    }

    // Step 1b: Check remote file paths in SSH/SCP/rsync/rclone commands (mode-aware)
    const remotePaths = extractRemoteFilePathsFromArgs(input.tool, output.args)
    for (const { path: remotePath, mode: remoteMode } of remotePaths) {
      const isRemoteAllowlistedPath = isAllowlisted(remotePath, sessionAllowlist)

      if (
        !isRemoteAllowlistedPath &&
        isPathBlockedForMode(remotePath, remoteMode, config.blockedFilePaths, config.writeProtectedPaths, config.whitelistedPaths)
      ) {
        sessionStats.recordBlock(input.tool, remotePath, "Blocked remote file path")

        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: input.tool,
          hook: "before",
          sessionId: input.sessionID,
          callId: input.callID,
          detections: [],
          blocked: true,
          blockReason: `Blocked remote file path: ${remotePath}`,
          redactedCount: 0,
        })

        if (config.notifications && canToast(toastState)) {
          try {
            await client.tui.showToast({
              body: { message: `🛡 Blocked: remote access to ${remotePath} denied`, variant: "error" as const },
            })
          } catch { /* toast failure is non-critical */ }
        }

        throw new Error(
          `Warden: Remote access to "${remotePath}" is blocked by security policy. ` +
          `This file may contain sensitive data (credentials, keys, secrets). ` +
          `If you need access, ask the user to temporarily allowlist it.`,
        )
      }
    }

    // Step 1c: Check bash shell file targets (redirections / tee / truncate / dd) against blocklist.
    // Write targets (>, >>, tee, truncate, dd of=) check blockedFilePaths + writeProtectedPaths.
    // Read targets (<) check blockedFilePaths only.
    // Without this, an agent could write to a blocked/protected file via shell redirection.
    if (input.tool === "bash" && typeof output.args.command === "string") {
      const { reads: bashReads, writes: bashWrites } = extractBashFileTargets(output.args.command as string)

      const checkAndBlock = async (target: string, mode: "read" | "write") => {
        if (isDynamicPathTarget(target)) {
          diagnosticLogger?.decision("input-sanitizer", input.tool, `BLOCKED dynamic bash ${mode} target: ${target}`)
          await auditLogger.log({
            timestamp: new Date().toISOString(),
            tool: input.tool,
            hook: "before",
            sessionId: input.sessionID,
            callId: input.callID,
            detections: [],
            blocked: true,
            blockReason: `Dynamic bash ${mode} target cannot be verified deterministically: ${target}`,
            redactedCount: 0,
          })
          throw new Error(
            `Warden: ${mode === "write" ? "Writing to" : "Reading"} dynamic shell target "${target}" is blocked by security policy. ` +
            `Use an explicit path so Warden can verify the target deterministically.`,
          )
        }
        if (isAllowlisted(target, sessionAllowlist, projectDir)) return
        if (!isPathBlockedForMode(target, mode, config.blockedFilePaths, config.writeProtectedPaths, config.whitelistedPaths, projectDir)) return

        diagnosticLogger?.decision("input-sanitizer", input.tool, `BLOCKED bash ${mode} target: ${target}`)
        sessionStats.recordBlock(input.tool, target, `Blocked bash ${mode} target`)

        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: input.tool,
          hook: "before",
          sessionId: input.sessionID,
          callId: input.callID,
          detections: [],
          blocked: true,
          blockReason: `Blocked bash ${mode} target: ${target}`,
          redactedCount: 0,
        })

        if (config.notifications && canToast(toastState)) {
          try {
            await client.tui.showToast({
              body: { message: `🛡 Blocked: shell ${mode} of ${target} denied`, variant: "error" as const },
            })
          } catch { /* toast failure is non-critical */ }
        }

        throw new Error(
          `Warden: ${mode === "write" ? "Writing to" : "Reading"} "${target}" via shell redirection is blocked by security policy. ` +
          `This file is on the sensitive-file blocklist or write-protection list. ` +
          `If you need to access it, ask the user to temporarily allowlist it.`,
        )
      }

      for (const target of bashWrites) {
        await checkAndBlock(target, "write")
      }
      for (const target of bashReads) {
        await checkAndBlock(target, "read")
      }
    }

    // Step 2: Regex pass — deep-scan all args and redact in-place
    const scanResult = deepScan(output.args, engine)
    let totalDetections = scanResult.totalMatches
    diagnosticLogger?.step("input-sanitizer", `Regex scan: ${totalDetections} detections`)

    if (scanResult.totalMatches > 0) {
      // Apply redacted args back
      Object.assign(output.args, scanResult.value as Record<string, unknown>)

      // Track detections by category
      const categoryMap = new Map<PatternCategory, number>()
      for (const match of scanResult.allMatches) {
        categoryMap.set(
          match.category,
          (categoryMap.get(match.category) || 0) + 1,
        )
      }
      for (const [cat, count] of categoryMap) {
        sessionStats.recordDetection(
          input.tool,
          cat,
          count,
          `Redacted ${count} secret(s) in input args`,
        )
      }
    }

    // Step 3: Indirect execution check (Layer 2) — bash only
    const indirectConfig = config.indirectExecution
    if (
      indirectConfig.enabled &&
      input.tool === "bash" &&
      safetyEvaluator &&
      safetyEvaluator.shouldEvaluate("bash") &&
      typeof output.args.command === "string"
    ) {
      const command = output.args.command as string
      const executedPaths = extractExecutedFilePaths(command, indirectConfig.interpreters)

      for (const execPath of executedPaths) {
        diagnosticLogger?.step("input-sanitizer", `Indirect execution: checking ${execPath}`)

        // System path → skip content check (normal command eval still applies)
        if (isSystemPath(execPath, indirectConfig.systemPaths)) {
          debugLog?.(`Indirect execution: ${execPath} → SKIP (system path)`)
          diagnosticLogger?.step("input-sanitizer", `Indirect execution: ${execPath} → system path, skipped`)
          continue
        }

        // File doesn't exist → skip (command eval still applies)
        const fileData = readFileContent(execPath, indirectConfig.maxContentSize)
        if (!fileData) {
          debugLog?.(`Indirect execution: ${execPath} → SKIP (file not found or unreadable)`)
          diagnosticLogger?.step("input-sanitizer", `Indirect execution: ${execPath} → not found, skipped`)
          continue
        }

        // Binary at non-system path → BLOCK immediately (no LLM)
        if (indirectConfig.blockBinaries && isBinaryFile(execPath)) {
          debugLog?.(`Indirect execution: ${execPath} → BLOCKED (binary at non-system path)`)
          diagnosticLogger?.decision("input-sanitizer", input.tool, `BLOCKED binary execution: ${execPath}`)

          await auditLogger.log({
            timestamp: new Date().toISOString(),
            tool: input.tool,
            hook: "before",
            sessionId: input.sessionID,
            callId: input.callID,
            detections: [],
            blocked: true,
            blockReason: `Indirect execution: binary file at non-system path: ${execPath}`,
            redactedCount: totalDetections,
          })

          if (config.notifications && canToast(toastState)) {
            try {
              await client.tui.showToast({
                body: { message: `🛡 Blocked: binary execution at ${execPath}`, variant: "error" as const },
              })
            } catch { /* toast failure is non-critical */ }
          }

          throw new Error(
            `Warden: Execution of binary file at non-system path blocked.\n` +
            `File: ${execPath}\n` +
            `Binary files at non-system paths cannot be verified for safety. ` +
            `Use a system-installed binary or ask the user to review and approve.`,
          )
        }

        // Build content with truncation notice
        let contentForEval = fileData.content
        if (fileData.truncated) {
          contentForEval += `\n\n[TRUNCATED: File exceeded ${indirectConfig.maxContentSize} bytes. Only the first ${indirectConfig.maxContentSize} bytes are shown.]`
        }

        // Check if file was written by agent
        const writtenByAgent = writtenFileRegistry.has(execPath)

        // LLM evaluation of file content
        debugLog?.(`Indirect execution: ${execPath} → evaluating content (${contentForEval.length} chars, agentWritten=${writtenByAgent})`)

        if (config.notifications && canToast(toastState)) {
          try {
            await client.tui.showToast({
              body: {
                message: `Scanning file content: ${execPath.substring(execPath.lastIndexOf("/") + 1)}`,
                variant: "info" as const,
              },
            })
          } catch { /* toast failure is non-critical */ }
        }

        const fileEvalResult = await safetyEvaluator.evaluateFileExecution(
          command, execPath, contentForEval, writtenByAgent,
        )

        diagnosticLogger?.decision("input-sanitizer", input.tool, `File content eval for ${execPath}: ${fileEvalResult.recommendation} (risk=${fileEvalResult.riskLevel})`, {
          safe: fileEvalResult.safe,
          riskLevel: fileEvalResult.riskLevel,
          recommendation: fileEvalResult.recommendation,
          riskDimensions: fileEvalResult.riskDimensions,
          writtenByAgent,
        })

        if (fileEvalResult.recommendation === "block") {
          await auditLogger.log({
            timestamp: new Date().toISOString(),
            tool: input.tool,
            hook: "before",
            sessionId: input.sessionID,
            callId: input.callID,
            detections: [],
            blocked: true,
            blockReason: `Indirect execution: file content blocked: ${execPath} — ${fileEvalResult.explanation}`,
            redactedCount: totalDetections,
            safetyEvaluation: fileEvalResult,
          })

          if (config.notifications && canToast(toastState)) {
            try {
              await client.tui.showToast({
                body: { message: `🛡 Blocked: malicious content in ${execPath.substring(execPath.lastIndexOf("/") + 1)}`, variant: "error" as const },
              })
            } catch { /* toast failure is non-critical */ }
          }

          const suggestion = fileEvalResult.suggestedAlternative
            ? `\nGuidance: ${fileEvalResult.suggestedAlternative}`
            : ""

          throw new Error(
            `Warden: Execution blocked — file content flagged as dangerous.\n` +
            `File: ${execPath}\n` +
            `Risk: ${fileEvalResult.riskLevel} | Dimensions: ${fileEvalResult.riskDimensions.join(", ")}\n` +
            `Reason: ${fileEvalResult.explanation}` +
            suggestion +
            `\nThe content of this file was analyzed and found to contain potentially harmful operations. ` +
            `If this is intentional, ask the user to review the file and confirm.`,
          )
        }

        if (fileEvalResult.recommendation === "warn") {
          if (config.notifications && canToast(toastState)) {
            try {
              await client.tui.showToast({
                body: {
                  message: `⚠️ File content warning: ${fileEvalResult.explanation.substring(0, 80)}`,
                  variant: "warning" as const,
                },
              })
            } catch { /* toast failure is non-critical */ }
          }
        }
      }
    }

    // Step 4: LLM safety evaluation (for actionable tools)
    const safetyActionMode = config.llm.safetyEvaluator.actionMode
    let safetyResult = null

    // Skip safety eval if already evaluated by permission.ask handler
    const alreadyEvaluated = evaluatedCalls.has(input.callID)
    if (alreadyEvaluated) {
      debugLog?.(`Input hook: tool=${input.tool} callID=${input.callID} → SKIPPED (already evaluated by permission.ask)`)
    }

    // Log bypass for audit trail when safety evaluator would have evaluated
    if (
      !alreadyEvaluated &&
      safetyEvaluator &&
      safetyEvaluator.shouldEvaluate(input.tool) &&
      safetyEvaluator.isBypassed(input.tool, output.args)
    ) {
      debugLog?.(`Input hook: tool=${input.tool} → BYPASSED by command pattern`)
      diagnosticLogger?.decision("input-sanitizer", input.tool, "Safety eval BYPASSED by command pattern")
      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: input.tool,
        hook: "before",
        sessionId: input.sessionID,
        callId: input.callID,
        detections: scanResult.allMatches.map((m) => ({
          patternId: m.patternId,
          category: m.category,
          confidence: m.confidence,
        })),
        blocked: false,
        blockReason: "Safety evaluation bypassed by command pattern match",
        redactedCount: totalDetections,
      })

      if (config.notifications && canToast(toastState)) {
        try {
          const cmdPreview = ((output.args.command as string) || input.tool).substring(0, 60)
          await client.tui.showToast({
            body: {
              message: `Approved by ruleset: ${cmdPreview}`,
              variant: "info" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }
    }

    if (
      !alreadyEvaluated &&
      safetyEvaluator &&
      safetyEvaluator.shouldEvaluate(input.tool) &&
      !safetyEvaluator.isBypassed(input.tool, output.args)
    ) {
      // In "permission" mode, if we get here it means permission.ask didn't fire
      // for this tool (e.g., tool is auto-allowed in OpenCode config).
      // Fall back to "block" behavior for safety.
      const effectiveMode = safetyActionMode === "permission" ? "block" : safetyActionMode

      debugLog?.(`Input hook: tool=${input.tool} → safety eval triggered (actionMode=${safetyActionMode}, effective=${effectiveMode})`)

      if (config.notifications && canToast(toastState)) {
        try {
          const cmdPreview = ((output.args.command as string) || input.tool).substring(0, 60)
          await client.tui.showToast({
            body: {
              message: `Escalated to LLM: ${cmdPreview}`,
              variant: "info" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }

      safetyResult = await safetyEvaluator.evaluate(input.tool, output.args)
      diagnosticLogger?.decision("input-sanitizer", input.tool, `Safety eval result: ${safetyResult.recommendation} (risk=${safetyResult.riskLevel})`, {
        safe: safetyResult.safe,
        riskLevel: safetyResult.riskLevel,
        recommendation: safetyResult.recommendation,
        riskDimensions: safetyResult.riskDimensions,
      })
      sessionStats.recordSafetyEvaluation(input.tool, safetyResult)

      if (safetyResult.recommendation === "block") {
        if (effectiveMode === "warn") {
          // "warn" mode: show toast but don't throw
          if (config.notifications) {
            try {
              await client.tui.showToast({
                body: {
                  message: `⚠️ Safety warning: ${safetyResult.explanation.substring(0, 80)}`,
                  variant: "warning" as const,
                },
              })
            } catch { /* toast failure is non-critical */ }
          }
        } else {
          // "block" mode (default): throw to block the call
          await auditLogger.log({
            timestamp: new Date().toISOString(),
            tool: input.tool,
            hook: "before",
            sessionId: input.sessionID,
            callId: input.callID,
            detections: [],
            blocked: true,
            blockReason: `Safety evaluation: ${safetyResult.explanation}`,
            redactedCount: totalDetections,
            safetyEvaluation: safetyResult,
          })

          if (config.notifications && canToast(toastState)) {
            try {
              await client.tui.showToast({
                body: {
                  message: `🛡 Blocked: ${safetyResult.explanation.substring(0, 80)}`,
                  variant: "error" as const,
                },
              })
            } catch { /* toast failure is non-critical */ }
          }

          const suggestion = safetyResult.suggestedAlternative
            ? `\nGuidance: ${safetyResult.suggestedAlternative}`
            : ""

          throw new Error(
            `Warden: Tool call blocked by safety evaluation.\n` +
            `Risk: ${safetyResult.riskLevel} | Dimensions: ${safetyResult.riskDimensions.join(", ")}\n` +
            `Reason: ${safetyResult.explanation}` +
            suggestion +
            `\nThis command was flagged as potentially dangerous. If this is intentional, ask the user to confirm.`,
          )
        }
      }

      if (safetyResult.recommendation === "warn") {
        if (config.notifications && canToast(toastState)) {
          try {
            await client.tui.showToast({
              body: {
                message: `⚠️ Warning: ${safetyResult.explanation.substring(0, 80)}`,
                variant: "warning" as const,
              },
            })
          } catch { /* toast failure is non-critical */ }
        }
      }

      if (safetyResult.recommendation === "allow") {
        if (config.notifications && canToast(toastState)) {
          try {
            const cmdPreview = ((output.args.command as string) || input.tool).substring(0, 60)
            await client.tui.showToast({
              body: {
                message: `Approved by LLM (risk: ${safetyResult.riskLevel}): ${cmdPreview}`,
                variant: "success" as const,
              },
            })
          } catch { /* toast failure is non-critical */ }
        }
      }
    }

    // Step 5: Write-time tracking (Layer 1) — record write/edit file paths
    if ((input.tool === "write" || input.tool === "edit") && indirectConfig.enabled) {
      const writtenPath = extractFilePath(input.tool, output.args)
      if (writtenPath) {
        const metadata: WrittenFileMetadata = {
          timestamp: new Date().toISOString(),
          tool: input.tool,
          filePath: writtenPath,
          hasExecutableExtension: hasExecutableExtension(writtenPath, indirectConfig.scriptExtensions),
        }
        writtenFileRegistry.set(writtenPath, metadata)
        debugLog?.(`Write tracking: recorded ${writtenPath} (executable=${metadata.hasExecutableExtension})`)
        diagnosticLogger?.step("input-sanitizer", `Write tracking: recorded ${writtenPath}`)
      }
    }

    // Step 6: Audit log
    await auditLogger.log({
      timestamp: new Date().toISOString(),
      tool: input.tool,
      hook: "before",
      sessionId: input.sessionID,
      callId: input.callID,
      detections: scanResult.allMatches.map((m) => ({
        patternId: m.patternId,
        category: m.category,
        confidence: m.confidence,
      })),
      blocked: false,
      redactedCount: totalDetections,
      safetyEvaluation: safetyResult ?? undefined,
    })

    if (totalDetections > 0 && config.notifications && canToast(toastState)) {
      try {
        await client.tui.showToast({
          body: {
            message: `🔒 Redacted ${totalDetections} secret(s) in ${input.tool} input`,
            variant: "warning" as const,
          },
        })
      } catch { /* toast failure is non-critical */ }
    }

    if (totalDetections === 0 && !safetyResult) {
      sessionStats.recordPass(input.tool)
    }

    diagnosticLogger?.hookEnd("input-sanitizer", input.tool, input.callID, Date.now() - hookStart, {
      outcome: totalDetections > 0 ? "redacted" : safetyResult ? `safety-${safetyResult.recommendation}` : "pass",
      detections: totalDetections,
    })
  }
}
