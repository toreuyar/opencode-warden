import type { DetectionEngine } from "../detection/engine.js"
import type { AuditLogger } from "../audit/index.js"
import type { SessionStats } from "../audit/session-stats.js"
import type { SafetyEvaluator, SafetyEvaluationResult } from "../llm/safety-evaluator.js"
import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type {
  SecurityGuardConfig,
  PluginClient,
  ToastState,
  PatternCategory,
  WrittenFileMetadata,
} from "../types.js"
import { isAllowlisted, isPathBlockedForMode, isRedactionExempt, extractFileTargets, extractRemoteFilePathsFromArgs, isDynamicPathTarget } from "../utils/paths.js"
import { canonicalToolName, isToolInList } from "../utils/tool-compat.js"
import { deepScan } from "../utils/deep-scan.js"
import {
  extractExecutedFilePaths,
  isSystemPath,
  isBinaryFile,
  readFileContent,
  hasExecutableExtension,
} from "../utils/script-detection.js"
import { isRemoteCommand } from "../utils/ssh.js"
import { hasSequentialShellBatch, SHELL_SEQUENCE_BLOCK_MESSAGE, SHELL_SEQUENCE_BLOCK_REASON } from "../utils/shell-sequence.js"

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

    // Policy vocabulary is V2-canonical (`shell`, `subagent`), but runtime
    // callers may still supply legacy names (`bash`, `task`). Every policy
    // check below is alias-aware.
    const canonicalTool = canonicalToolName(input.tool)

    const debugLog = config.llm.debug
      ? (msg: string) => {
          client.app.log({
            body: { service: "warden", level: "info", message: msg },
          }).catch(() => {})
        }
      : undefined

    // Block tools on the blocklist (e.g., "subagent"/legacy "task" to prevent
    // subagent spawning). Alias-aware on both sides.
    if (isToolInList(input.tool, config.blockedTools)) {
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

    // Skip excluded tools (alias-aware: excluded "shell" also excludes legacy "bash")
    if (isToolInList(input.tool, config.excludedTools)) {
      debugLog?.(`Input hook: tool=${input.tool} → SKIPPED (excluded)`)
      diagnosticLogger?.hookEnd("input-sanitizer", input.tool, input.callID, Date.now() - hookStart, { outcome: "skipped", reason: "excluded tool" })
      return
    }

    // SSH-only mode: skip all non-remote commands
    if (config.sshOnlyMode) {
      if (canonicalTool === "shell") {
        const command = typeof output.args.command === "string" ? output.args.command : ""
        if (!isRemoteCommand(command)) {
          debugLog?.(`Input hook: tool=${input.tool} → SKIPPED (sshOnlyMode: not a remote command)`)
          diagnosticLogger?.hookEnd("input-sanitizer", input.tool, input.callID, Date.now() - hookStart, { outcome: "skipped", reason: "sshOnlyMode: not a remote command" })
          return
        }
      } else {
        debugLog?.(`Input hook: tool=${input.tool} → SKIPPED (sshOnlyMode: non-shell tool)`)
        diagnosticLogger?.hookEnd("input-sanitizer", input.tool, input.callID, Date.now() - hookStart, { outcome: "skipped", reason: "sshOnlyMode: non-shell tool" })
        return
      }
    }

    const enforceShellSequence = async (command: unknown) => {
      if (!hasSequentialShellBatch(input.tool, command)) return

      sessionStats.recordBlock(input.tool, "", SHELL_SEQUENCE_BLOCK_REASON)
      diagnosticLogger?.decision("input-sanitizer", input.tool, SHELL_SEQUENCE_BLOCK_REASON)
      try {
        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: input.tool,
          hook: "before",
          sessionId: input.sessionID,
          callId: input.callID,
          detections: [],
          blocked: true,
          blockReason: SHELL_SEQUENCE_BLOCK_REASON,
          redactedCount: 0,
        })
      } catch { /* audit failure is non-critical */ }
      if (config.notifications && canToast(toastState)) {
        try {
          await client.tui.showToast({
            body: { message: `🛡 Blocked: ${SHELL_SEQUENCE_BLOCK_REASON}`, variant: "error" as const },
          })
        } catch { /* toast failure is non-critical */ }
      }
      throw new Error(SHELL_SEQUENCE_BLOCK_MESSAGE)
    }

    const originalCommand = output.args.command
    if (canonicalTool === "shell") await enforceShellSequence(originalCommand)

    // Step 1: Check every local file target (mode-aware). The shared
    // multi-target extractor covers V2 `path`, legacy `filePath`, all patch
    // add/delete/update/MOVE destinations, and shell redirection/read targets.
    // Whitelist wins per target; write targets also honor writeProtectedPaths.
    const fileTargets = extractFileTargets(input.tool, output.args)

    const checkAndBlockLocalTarget = async (target: string, mode: "read" | "write") => {
      // Dynamic shell paths cannot be verified deterministically. Keep the
      // existing fail-closed behavior for every extracted shell target.
      if (canonicalTool === "shell" && isDynamicPathTarget(target)) {
        diagnosticLogger?.decision("input-sanitizer", input.tool, `BLOCKED dynamic shell ${mode} target: ${target}`)
        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: input.tool,
          hook: "before",
          sessionId: input.sessionID,
          callId: input.callID,
          detections: [],
          blocked: true,
          blockReason: `Dynamic shell ${mode} target cannot be verified deterministically: ${target}`,
          redactedCount: 0,
        })
        throw new Error(
          `Warden: ${mode === "write" ? "Writing to" : "Reading"} dynamic shell target "${target}" is blocked by security policy. ` +
          `Use an explicit path so Warden can verify the target deterministically.`,
        )
      }

      if (isAllowlisted(target, sessionAllowlist, projectDir)) return
      if (!isPathBlockedForMode(target, mode, config.blockedFilePaths, config.writeProtectedPaths, config.whitelistedPaths, projectDir)) return

      diagnosticLogger?.decision("input-sanitizer", input.tool, `BLOCKED file path (${mode}): ${target}`)
      sessionStats.recordBlock(input.tool, target, `Blocked file path (${mode})`)

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: input.tool,
        hook: "before",
        sessionId: input.sessionID,
        callId: input.callID,
        detections: [],
        blocked: true,
        blockReason: `Blocked file path (${mode}): ${target}`,
        redactedCount: 0,
      })

      if (config.notifications && canToast(toastState)) {
        try {
          await client.tui.showToast({
            body: {
              message: canonicalTool === "shell"
                ? `🛡 Blocked: shell ${mode} of ${target} denied`
                : `🛡 Blocked: ${target} access denied`,
              variant: "error" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }

      throw new Error(
        canonicalTool === "shell"
          ? `Warden: ${mode === "write" ? "Writing to" : "Reading"} "${target}" via shell is blocked by security policy. ` +
            `This file is on the sensitive-file blocklist or write-protection list. ` +
            `If you need to access it, ask the user to temporarily allowlist it.`
          : `Warden: Access to "${target}" is blocked by security policy. ` +
            `This file may contain sensitive data (credentials, keys, secrets). ` +
            `If you need access, ask the user to temporarily allowlist it.`,
      )
    }

    for (const target of fileTargets) {
      await checkAndBlockLocalTarget(target.path, target.mode)
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

    // Step 2: Regex pass — deep-scan all args and redact in-place.
    // Skipped when ANY of these apply:
    //   - redactionEnabled is false (global kill switch for ALL tools)
    //   - redactOnWrite is false AND this is a write/edit/patch tool
    //   - every write target matches redactionExemptPaths (all write/edit/patch
    //     targets including patch moves, local shell redirection/tee/truncate/dd
    //     targets, or remote upload via SSH/SCP/rsync/rclone)
    // File blocking and LLM safety eval still apply — only secret redaction is skipped.
    const isWriteTool = canonicalTool === "write" || canonicalTool === "edit" || canonicalTool === "patch"
    const allDisabled = !config.redactionEnabled
    const writeDisabled = isWriteTool && !config.redactOnWrite

    // Collect every write target this call touches. Multi-target on purpose:
    // a patch may update one file and move another, and a shell command may
    // tee to several files. Exemption is all-or-nothing.
    const writeTargets: Array<{ path: string; host?: string }> = fileTargets
      .filter((target) => target.mode === "write")
      .map((target) => ({ path: target.path }))
    if (canonicalTool === "shell") {
      for (const { host, path, mode } of extractRemoteFilePathsFromArgs(input.tool, output.args)) {
        if (mode === "write") writeTargets.push({ path, host })
      }
    }

    const exemptedTarget = writeTargets.find((t) =>
      isRedactionExempt(t.path, config.redactionExemptPaths, { cwd: projectDir, host: t.host }),
    )
    const pathExempt = writeTargets.length > 0 && writeTargets.every((t) =>
      isRedactionExempt(t.path, config.redactionExemptPaths, { cwd: projectDir, host: t.host }),
    )
    const redactionExempt = allDisabled || writeDisabled || pathExempt

    let totalDetections = 0
    let scanResult: { value: unknown; totalMatches: number; allMatches: import("../types.js").DetectionMatch[] }

    if (redactionExempt) {
      const reason = allDisabled
        ? "Redaction disabled (redactionEnabled=false)"
        : writeDisabled
          ? "Redaction disabled (redactOnWrite=false)"
          : exemptedTarget!.host
            ? `Redaction exempt (path matches redactionExemptPaths): [${exemptedTarget!.host}]${exemptedTarget!.path}`
            : `Redaction exempt (path matches redactionExemptPaths): ${exemptedTarget!.path}`
      debugLog?.(`Input hook: tool=${input.tool} → ${reason}`)
      diagnosticLogger?.decision("input-sanitizer", input.tool, reason)
      scanResult = { value: output.args, totalMatches: 0, allMatches: [] }
    } else {
      scanResult = deepScan(output.args, engine)
      totalDetections = scanResult.totalMatches
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
    }

    if (canonicalTool === "shell" && output.args.command !== originalCommand) {
      await enforceShellSequence(output.args.command)
    }

    // Before either file-content evaluation or the contextual safety verdict.
    const precheck =
      config.llm.enabled && config.llm.safetyEvaluator.complexityPrecheck?.enabled &&
      canonicalTool === "shell" && safetyEvaluator?.shouldEvaluate(input.tool)
        ? await safetyEvaluator.precheckComplexity(input.tool, output.args)
        : undefined
    if (precheck && precheck !== "continue") {
      sessionStats.recordSafetyEvaluation(input.tool, precheck)
      diagnosticLogger?.decision("input-sanitizer", input.tool, precheck.explanation)
      try {
        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: input.tool,
          hook: "before",
          sessionId: input.sessionID,
          callId: input.callID,
          detections: [],
          blocked: true,
          blockReason: precheck.explanation,
          redactedCount: totalDetections,
          safetyEvaluation: precheck,
        })
      } catch { /* audit failure is non-critical */ }
      if (config.notifications && canToast(toastState)) {
        try {
          await client.tui.showToast({
            body: { message: `🛡 Blocked: ${precheck.explanation}`, variant: "error" as const },
          })
        } catch { /* toast failure is non-critical */ }
      }
      throw new Error(precheck.explanation)
    }

    // Step 3: Indirect execution check (Layer 2) — shell only
    const indirectConfig = config.indirectExecution
    if (
      indirectConfig.enabled &&
      canonicalTool === "shell" &&
      safetyEvaluator &&
      safetyEvaluator.shouldEvaluate(input.tool) &&
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

        if (fileEvalResult.recommendation === "block" || fileEvalResult.evaluationFailed) {
          const evalFailed = fileEvalResult.evaluationFailed === true
          await auditLogger.log({
            timestamp: new Date().toISOString(),
            tool: input.tool,
            hook: "before",
            sessionId: input.sessionID,
            callId: input.callID,
            detections: [],
            blocked: true,
            blockReason: evalFailed
              ? `Indirect execution: file content evaluation unavailable: ${execPath} — blocking for safety`
              : `Indirect execution: file content blocked: ${execPath} — ${fileEvalResult.explanation}`,
            redactedCount: totalDetections,
            safetyEvaluation: fileEvalResult,
          })

          if (config.notifications && canToast(toastState)) {
            try {
              await client.tui.showToast({
                body: {
                  message: evalFailed
                    ? `🛡 Blocked: file content evaluation unavailable for ${execPath.substring(execPath.lastIndexOf("/") + 1)}`
                    : `🛡 Blocked: malicious content in ${execPath.substring(execPath.lastIndexOf("/") + 1)}`,
                  variant: "error" as const,
                },
              })
            } catch { /* toast failure is non-critical */ }
          }

          const suggestion = !evalFailed && fileEvalResult.suggestedAlternative
            ? `\nGuidance: ${fileEvalResult.suggestedAlternative}`
            : ""

          throw new Error(
            evalFailed
              ? `Warden: Execution blocked — file content could not be evaluated (fail-closed).\n` +
                `File: ${execPath}\n` +
                `The safety evaluator is unavailable, misconfigured, timed out, or returned an unusable response. ` +
                `LLM-evaluated operations remain blocked until the evaluator is working.`
              : `Warden: Execution blocked — file content flagged as dangerous.\n` +
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
    let safetyResult: SafetyEvaluationResult | null = null

    // Do not let an earlier permission verdict for the original arguments
    // substitute for evaluation of a candidate whose arguments may be redacted.
    const alreadyEvaluated = precheck !== "continue" && evaluatedCalls.has(input.callID)
    if (alreadyEvaluated) {
      debugLog?.(`Input hook: tool=${input.tool} callID=${input.callID} → SKIPPED (already evaluated by permission.ask)`)
    }

    // This mirrors SafetyEvaluator.shouldEvaluate without needing an evaluator
    // instance. It lets the hook distinguish "this component is disabled"
    // (deterministic-only mode, no block) from "this component is enabled but
    // its evaluator is missing" (misconfiguration, must block).
    const safetyComponentEvaluable =
      config.llm.enabled &&
      config.llm.safetyEvaluator.enabled &&
      isToolInList(input.tool, config.llm.safetyEvaluator.tools ?? [])

    const blockUnavailableEvaluator = async (detail: string): Promise<never> => {
      const reason = `Safety evaluator unavailable — ${detail} (fail-closed)`
      diagnosticLogger?.decision("input-sanitizer", input.tool, reason)

      await auditLogger.log({
        timestamp: new Date().toISOString(),
        tool: input.tool,
        hook: "before",
        sessionId: input.sessionID,
        callId: input.callID,
        detections: [],
        blocked: true,
        blockReason: reason,
        redactedCount: totalDetections,
      })

      if (config.notifications && canToast(toastState)) {
        try {
          await client.tui.showToast({
            body: {
              message: `🛡 Blocked: safety evaluator unavailable (fail-closed)`,
              variant: "error" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      }

      throw new Error(
        `Warden: Tool call blocked — safety evaluator unavailable (fail-closed).\n` +
        `The LLM safety component is enabled, but no evaluator is available. ` +
        `LLM-evaluated operations remain blocked until the evaluator is working.`,
      )
    }

    if (!alreadyEvaluated && !safetyEvaluator && safetyComponentEvaluable) {
      await blockUnavailableEvaluator("tool call cannot be evaluated")
    }

    // Log bypass for audit trail when safety evaluator would have evaluated
    if (
      !alreadyEvaluated &&
      precheck !== "continue" &&
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
      (precheck === "continue" || !safetyEvaluator.isBypassed(input.tool, output.args))
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

      if (safetyResult.recommendation === "block" || safetyResult.evaluationFailed) {
        const evaluationFailed = safetyResult.evaluationFailed === true

        if (effectiveMode === "warn" && !evaluationFailed) {
          // "warn" mode: a genuine model risk verdict may be downgraded to a
          // warning. An evaluator outage may NOT — it always throws below.
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
          // "block" mode (default), or any evaluator failure regardless of mode
          const blockReason = evaluationFailed
            ? "Safety evaluator unavailable — blocking for safety (fail-closed)"
            : `Safety evaluation: ${safetyResult.explanation}`

          await auditLogger.log({
            timestamp: new Date().toISOString(),
            tool: input.tool,
            hook: "before",
            sessionId: input.sessionID,
            callId: input.callID,
            detections: [],
            blocked: true,
            blockReason,
            redactedCount: totalDetections,
            safetyEvaluation: safetyResult,
          })

          if (config.notifications && canToast(toastState)) {
            try {
              await client.tui.showToast({
                body: {
                  message: evaluationFailed
                    ? `🛡 Blocked: safety evaluator unavailable (fail-closed)`
                    : `🛡 Blocked: ${safetyResult.explanation.substring(0, 80)}`,
                  variant: "error" as const,
                },
              })
            } catch { /* toast failure is non-critical */ }
          }

          const suggestion = !evaluationFailed && safetyResult.suggestedAlternative
            ? `\nGuidance: ${safetyResult.suggestedAlternative}`
            : ""

          throw new Error(
            evaluationFailed
              ? `Warden: Tool call blocked — safety evaluator unavailable (fail-closed).\n` +
                `The evaluator is unreachable, misconfigured, timed out, or returned an unusable response. ` +
                `LLM-evaluated operations remain blocked until the evaluator is working.`
              : `Warden: Tool call blocked by safety evaluation.\n` +
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

    // Step 5: Write-time tracking (Layer 1) — record every write target.
    // Covers V2 write/edit `path`, legacy `filePath`, and all patch
    // add/delete/update/move destinations so indirect execution can flag
    // files the agent just created or modified.
    if (indirectConfig.enabled && isWriteTool) {
      const writtenTargets = fileTargets.filter((target) => target.mode === "write")
      for (const { path: writtenPath } of writtenTargets) {
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
      blockReason: redactionExempt
        ? allDisabled
          ? "Redaction disabled (redactionEnabled=false)"
          : writeDisabled
            ? "Redaction disabled (redactOnWrite=false)"
            : exemptedTarget!.host
              ? `Redaction exempt (path matches redactionExemptPaths): [${exemptedTarget!.host}]${exemptedTarget!.path}`
              : `Redaction exempt (path matches redactionExemptPaths): ${exemptedTarget!.path}`
        : undefined,
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
