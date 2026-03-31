import type { DetectionEngine } from "../detection/engine.js"
import type { AuditLogger } from "../audit/index.js"
import type { SessionStats } from "../audit/session-stats.js"
import type { LlmSanitizer } from "../llm/index.js"
import type { OutputTriageEvaluator } from "../llm/output-triage.js"
import type { OutputTextTriageEvaluator } from "../llm/output-text-triage.js"
import type { LlmSanitizeFinding } from "../types.js"
import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type {
  SecurityGuardConfig,
  PluginClient,
  ToastState,
  PatternCategory,
} from "../types.js"
import {
  stripSudo,
  hasDangerousMetachars,
  isPipedCommandSafe,
} from "../utils/command-patterns.js"
import { isBlockedPath } from "../utils/paths.js"
import { isRemoteCommand } from "../utils/ssh.js"

interface OutputRedactorDeps {
  engine: DetectionEngine
  config: SecurityGuardConfig
  auditLogger: AuditLogger
  sessionStats: SessionStats
  client: PluginClient
  llmSanitizer: LlmSanitizer | null
  outputTriage: OutputTriageEvaluator | null
  outputTextTriage: OutputTextTriageEvaluator | null
  toastState: ToastState
  diagnosticLogger: DiagnosticLogger | null
}

interface RedactionResult {
  redacted: string
  totalReplacements: number
  hasMismatch: boolean
  mismatchDetails: string[]
}

function applyRedactions(text: string, findings: LlmSanitizeFinding[]): RedactionResult {
  let redacted = text
  let totalReplacements = 0
  let hasMismatch = false
  const mismatchDetails: string[] = []

  for (const finding of findings) {
    // Count actual occurrences via indexOf loop
    let actualCount = 0
    let searchPos = 0
    while (true) {
      const idx = redacted.indexOf(finding.sensitive, searchPos)
      if (idx === -1) break
      actualCount++
      searchPos = idx + finding.sensitive.length
    }

    if (actualCount === 0) {
      // Hallucination: LLM reported a string that doesn't exist in text
      hasMismatch = true
      mismatchDetails.push(
        `Hallucination: "${finding.sensitive.substring(0, 20)}..." (category=${finding.category}) not found in output`,
      )
      continue
    }

    if (actualCount !== finding.occurrences) {
      // Miscount: LLM reported wrong occurrence count
      hasMismatch = true
      mismatchDetails.push(
        `Miscount: "${finding.sensitive.substring(0, 20)}..." (category=${finding.category}) reported=${finding.occurrences} actual=${actualCount}`,
      )
    }

    // Replace all occurrences of the sensitive string
    redacted = redacted.replaceAll(finding.sensitive, "[REDACTED]")
    totalReplacements += actualCount
  }

  return { redacted, totalReplacements, hasMismatch, mismatchDetails }
}

function canToast(state: ToastState): boolean {
  const now = Date.now()
  if (now - state.lastToastTime < state.minInterval) return false
  state.lastToastTime = now
  return true
}

export function createOutputRedactor(deps: OutputRedactorDeps) {
  const {
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
  } = deps

  const outputBypassPrefixes = config.llm.outputSanitizer.bypassedCommands

  /**
   * Check if a bash command's output can bypass LLM sanitization.
   * Only applies to "bash" tool. Uses the same sudo-stripping and
   * pipe-chain logic as the safety evaluator, but with the output
   * sanitizer's own bypass list.
   */
  function isOutputBypassed(tool: string, args?: Record<string, unknown>): boolean {
    if (tool !== "bash") return false
    const rawCommand = typeof args?.command === "string" ? args.command : ""
    if (!rawCommand) return false

    const command = stripSudo(rawCommand)
    if (hasDangerousMetachars(command)) return false

    // Simple prefix match (no pipes)
    if (!command.includes("|")) {
      return outputBypassPrefixes.some((prefix) =>
        command.trimStart().startsWith(prefix),
      )
    }

    // Pipe chain: first segment must match bypass prefix, rest must be safe pipe targets
    // Pass empty compiled patterns array — output bypass only uses prefix matching
    return isPipedCommandSafe(command, outputBypassPrefixes, [])
  }

  return async (
    input: { tool: string; sessionID: string; callID: string; args?: Record<string, unknown> },
    output: { output: string; title: string; metadata: Record<string, unknown> },
  ) => {
    const hookStart = Date.now()
    const outputLen = typeof output.output === "string" ? output.output.length : 0
    diagnosticLogger?.hookStart("output-redactor", input.tool, input.callID, input.sessionID, { outputLength: outputLen })

    const debugLog = config.llm.debug
      ? (msg: string) => {
          client.app.log({
            body: { service: "security-guard", level: "info", message: msg },
          }).catch(() => {})
        }
      : undefined

    const outputActionMode = config.llm.outputSanitizer.actionMode

    // Skip excluded tools
    if (config.excludedTools.includes(input.tool)) {
      debugLog?.(`Output hook: tool=${input.tool} → SKIPPED (excluded)`)
      diagnosticLogger?.hookEnd("output-redactor", input.tool, input.callID, Date.now() - hookStart, { outcome: "skipped", reason: "excluded tool" })
      return
    }

    // SSH-only mode: skip all non-remote commands
    if (config.sshOnlyMode) {
      if (input.tool === "bash") {
        const command = typeof input.args?.command === "string" ? input.args.command : ""
        if (!isRemoteCommand(command)) {
          debugLog?.(`Output hook: tool=${input.tool} → SKIPPED (sshOnlyMode: not a remote command)`)
          diagnosticLogger?.hookEnd("output-redactor", input.tool, input.callID, Date.now() - hookStart, { outcome: "skipped", reason: "sshOnlyMode: not a remote command" })
          return
        }
      } else {
        debugLog?.(`Output hook: tool=${input.tool} → SKIPPED (sshOnlyMode: non-bash tool)`)
        diagnosticLogger?.hookEnd("output-redactor", input.tool, input.callID, Date.now() - hookStart, { outcome: "skipped", reason: "sshOnlyMode: non-bash tool" })
        return
      }
    }

    // Glob output filtering: strip blocked paths from glob results
    if (input.tool === "glob" && typeof output.output === "string" && output.output.length > 0) {
      const lines = output.output.split("\n")
      const filtered: string[] = []
      let strippedCount = 0
      for (const line of lines) {
        const trimmed = line.trim()
        if (trimmed && isBlockedPath(trimmed, config.blockedFilePaths, config.whitelistedPaths)) {
          strippedCount++
        } else {
          filtered.push(line)
        }
      }
      if (strippedCount > 0) {
        output.output = filtered.join("\n")
        diagnosticLogger?.step("output-redactor", `Glob filter: stripped ${strippedCount} blocked path(s)`)
      }
    }

    let totalDetections = 0
    const allDetectionCategories: PatternCategory[] = []

    // Pass 1: Regex detection (fast, deterministic)
    if (typeof output.output === "string" && output.output.length > 0) {
      const result = engine.scan(output.output)
      if (result.hasDetections) {
        // In "pass" mode, don't redact — just count detections
        if (outputActionMode !== "pass") {
          output.output = result.redacted
        }
        totalDetections += result.matches.length

        const categoryMap = new Map<PatternCategory, number>()
        for (const match of result.matches) {
          categoryMap.set(
            match.category,
            (categoryMap.get(match.category) || 0) + 1,
          )
          allDetectionCategories.push(match.category)
        }
        for (const [cat, count] of categoryMap) {
          sessionStats.recordDetection(
            input.tool,
            cat,
            count,
            outputActionMode === "pass"
              ? `Detected ${count} secret(s) in output (pass mode — not redacted)`
              : `Redacted ${count} secret(s) in output`,
          )
        }
      }
    }

    // Scan title too
    if (typeof output.title === "string" && output.title.length > 0) {
      const titleResult = engine.scan(output.title)
      if (titleResult.hasDetections) {
        if (outputActionMode !== "pass") {
          output.title = titleResult.redacted
        }
        totalDetections += titleResult.matches.length
      }
    }

    diagnosticLogger?.step("output-redactor", `Regex scan: ${totalDetections} detections`)

    // Pass 2: LLM sanitization (context-aware, catches novel patterns)
    // Skip LLM entirely in "pass" mode — no redaction should occur
    let llmDetections = 0
    let llmBlocked = false
    if (outputActionMode !== "pass" && llmSanitizer && llmSanitizer.shouldSanitize(input.tool)) {
      // Deterministic bypass: skip LLM entirely for commands whose output is known safe
      // Check this FIRST — bypassed commands should not be subject to size limits
      let outputBypassed = false
      if (isOutputBypassed(input.tool, input.args)) {
        outputBypassed = true
        debugLog?.(
          `Output hook: tool=${input.tool} → OUTPUT BYPASSED (deterministic: command output known safe)`,
        )
        diagnosticLogger?.decision("output-redactor", input.tool, "OUTPUT BYPASSED (deterministic: command output known safe)")
      }

      // Skip LLM if output exceeds maxOutputSize (0 = no limit)
      // Only applies to non-bypassed commands — bypassed output is trusted regardless of size
      if (!outputBypassed) {
        const maxOutputSize = config.llm.outputSanitizer.maxOutputSize
        const outputSize = typeof output.output === "string" ? output.output.length : 0
        if (maxOutputSize > 0 && outputSize > maxOutputSize) {
          debugLog?.(
            `Output hook: tool=${input.tool} → LLM sanitization SKIPPED (output size ${outputSize} exceeds limit ${maxOutputSize})`,
          )
          output.output =
            `[BLOCKED] Output too large for security scanning (${outputSize} chars, limit ${maxOutputSize}). ` +
            `Use more targeted commands to reduce output size:\n` +
            `  - Use head/tail with -n to limit lines (e.g., head -n 50)\n` +
            `  - Use grep to filter relevant lines\n` +
            `  - Pipe through wc -l to count instead of listing\n` +
            `  - Read specific line ranges instead of entire files`
          output.title = "[BLOCKED] Output too large for security scanning"
          llmBlocked = true

          if (config.notifications) {
            try {
              await client.tui.showToast({
                body: {
                  message: `Output blocked: too large for scanning (${outputSize} chars, limit ${maxOutputSize}) — ${input.tool}`,
                  variant: "error" as const,
                },
              })
            } catch { /* toast failure is non-critical */ }
          }
        }
      }

      // Skip LLM if regex found nothing and skipWhenRegexClean is enabled
      const shouldSkip =
        !llmBlocked && !outputBypassed && config.llm.outputSanitizer.skipWhenRegexClean && totalDetections === 0

      if (shouldSkip) {
        debugLog?.(
          `Output hook: tool=${input.tool} → LLM sanitization SKIPPED (regex clean)`,
        )
      }

      if (!shouldSkip && !llmBlocked && !outputBypassed && !llmSanitizer.isAvailable()) {
        // All providers are on cooldown or unavailable — block output
        debugLog?.(
          `Output hook: tool=${input.tool} → no LLM providers available — BLOCKING output for safety`,
        )
        llmBlocked = true
        output.output = "[BLOCKED] No LLM providers available — output withheld for safety"
        output.title = "[BLOCKED] Output withheld"

        if (config.notifications) {
          try {
            await client.tui.showToast({
              body: {
                message: `🛡 Output blocked: no LLM providers available for ${input.tool}`,
                variant: "error" as const,
              },
            })
          } catch { /* toast failure is non-critical */ }
        }
      }

      // Layer 1: Command triage — ask lightweight LLM if this command's output needs sanitization
      let commandTriagedClean = false
      if (!shouldSkip && !llmBlocked && !outputBypassed && llmSanitizer.isAvailable() && outputTriage && outputTriage.isEnabled()) {
        try {
          const triageResult = await outputTriage.evaluate(input.tool, input.args || {})
          if (!triageResult.needsSanitization) {
            commandTriagedClean = true
            debugLog?.(
              `Output hook: tool=${input.tool} → COMMAND TRIAGED CLEAN: ${triageResult.reason}`,
            )
            diagnosticLogger?.decision("output-redactor", input.tool, `Command triage: CLEAN — ${triageResult.reason}`)
          } else {
            debugLog?.(
              `Output hook: tool=${input.tool} → command triage says sanitize: ${triageResult.reason}`,
            )
            diagnosticLogger?.decision("output-redactor", input.tool, `Command triage: NEEDS SANITIZATION — ${triageResult.reason}`)
          }
        } catch (err) {
          const errMsg = err instanceof Error ? err.message : String(err)
          debugLog?.(
            `Output hook: tool=${input.tool} → command triage FAILED — BLOCKING output: ${errMsg}`,
          )
          llmBlocked = true
          output.output = "[BLOCKED] Command triage failed — output withheld for safety"
          output.title = "[BLOCKED] Output withheld"

          if (config.notifications) {
            try {
              await client.tui.showToast({
                body: {
                  message: `🛡 Output blocked: command triage failed for ${input.tool}`,
                  variant: "error" as const,
                },
              })
            } catch { /* toast failure is non-critical */ }
          }
        }
      }

      // Layer 2: Text triage — scan actual output text for secrets (if command triage didn't clear it)
      let textTriagedClean = false
      if (!shouldSkip && !llmBlocked && !outputBypassed && !commandTriagedClean && llmSanitizer.isAvailable() && outputTextTriage && outputTextTriage.isEnabled()) {
        try {
          const textTriageResult = await outputTextTriage.evaluate(input.tool, input.args || {}, output.output)
          if (!textTriageResult.needsSanitization) {
            textTriagedClean = true
            debugLog?.(
              `Output hook: tool=${input.tool} → TEXT TRIAGED CLEAN: ${textTriageResult.reason}`,
            )
            diagnosticLogger?.decision("output-redactor", input.tool, `Text triage: CLEAN — ${textTriageResult.reason}`)
          } else {
            debugLog?.(
              `Output hook: tool=${input.tool} → text triage says sanitize: ${textTriageResult.reason}`,
            )
            diagnosticLogger?.decision("output-redactor", input.tool, `Text triage: NEEDS SANITIZATION — ${textTriageResult.reason}`)
          }
        } catch (err) {
          const errMsg = err instanceof Error ? err.message : String(err)
          debugLog?.(
            `Output hook: tool=${input.tool} → text triage FAILED — BLOCKING output: ${errMsg}`,
          )
          llmBlocked = true
          output.output = "[BLOCKED] Text triage failed — output withheld for safety"
          output.title = "[BLOCKED] Output withheld"

          if (config.notifications) {
            try {
              await client.tui.showToast({
                body: {
                  message: `🛡 Output blocked: text triage failed for ${input.tool}`,
                  variant: "error" as const,
                },
              })
            } catch { /* toast failure is non-critical */ }
          }
        }
      }

      // Layer 3: Sanitizer — detection-only LLM + plugin-side redaction
      const needsSanitizer = !shouldSkip && !llmBlocked && !outputBypassed && !commandTriagedClean && !textTriagedClean
      if (needsSanitizer && llmSanitizer.isAvailable()) {
        try {
          // Build rich context from tool name, args, and title
          const contextParts: string[] = [`Tool: ${input.tool}`]
          if (input.args && Object.keys(input.args).length > 0) {
            contextParts.push(`Arguments: ${JSON.stringify(input.args)}`)
          }
          if (output.title) {
            contextParts.push(`Title: ${output.title}`)
          }
          const llmContext = contextParts.join("\n")

          const llmResult = await llmSanitizer.sanitize(
            input.tool,
            output.output,
            llmContext,
          )

          if (llmResult.findings.length > 0) {
            // Plugin-side deterministic redaction
            const redactionResult = applyRedactions(output.output, llmResult.findings)

            if (redactionResult.hasMismatch) {
              // Finding verification failed — block output for safety
              debugLog?.(
                `Output hook: tool=${input.tool} → FINDING MISMATCH — BLOCKING output:\n${redactionResult.mismatchDetails.join("\n")}`,
              )
              llmBlocked = true
              output.output = `[BLOCKED] LLM sanitizer findings could not be verified — output withheld for safety (${redactionResult.mismatchDetails.length} issue(s))`
              output.title = "[BLOCKED] Output withheld"

              if (config.notifications) {
                try {
                  await client.tui.showToast({
                    body: {
                      message: `🛡 Output blocked: sanitizer finding mismatch for ${input.tool}`,
                      variant: "error" as const,
                    },
                  })
                } catch { /* toast failure is non-critical */ }
              }
            } else {
              output.output = redactionResult.redacted
              llmDetections = redactionResult.totalReplacements
              sessionStats.recordLlmDetections(llmDetections)
              diagnosticLogger?.decision("output-redactor", input.tool, `LLM sanitization: ${llmDetections} redaction(s) from ${llmResult.findings.length} finding(s)`)
            }
          } else {
            debugLog?.(`Output hook: tool=${input.tool} → LLM verified clean`)
            diagnosticLogger?.decision("output-redactor", input.tool, "LLM verified clean")
          }
        } catch (err) {
          const errMsg = err instanceof Error ? err.message : String(err)
          const isParseError = errMsg.includes("parsing failed")
          const isInconsistency = errMsg.includes("inconsistency")
          const isTimeout = errMsg.includes("timed out")

          // Fail closed: block output regardless of error type
          debugLog?.(
            `Output hook: tool=${input.tool} → LLM sanitization ${isTimeout ? "TIMED OUT" : isParseError ? "PARSE ERROR" : isInconsistency ? "INCONSISTENCY" : "FAILED"} — BLOCKING output for safety: ${errMsg}`,
          )
          llmBlocked = true
          output.output = isInconsistency
            ? "[BLOCKED] LLM reported secrets but provided no findings — output withheld for safety"
            : isParseError
              ? "[BLOCKED] LLM produced unparseable response — output withheld for safety (LLM is connected)"
              : isTimeout
                ? "[BLOCKED] LLM sanitization timed out — output withheld for safety"
                : "[BLOCKED] LLM sanitization failed — output withheld for safety"
          output.title = "[BLOCKED] Output withheld"

          if (config.notifications) {
            try {
              await client.tui.showToast({
                body: {
                  message: isInconsistency
                    ? `🛡 Output blocked: LLM inconsistency for ${input.tool}`
                    : isParseError
                      ? `🛡 Output blocked: LLM response unparseable for ${input.tool} (LLM connected)`
                      : `🛡 Output blocked: LLM sanitization ${isTimeout ? "timed out" : "failed"} for ${input.tool}`,
                  variant: "error" as const,
                },
              })
            } catch { /* toast failure is non-critical */ }
          }
        }
      }
    }

    // Audit log
    const regexDetections = totalDetections
    totalDetections += llmDetections

    await auditLogger.log({
      timestamp: new Date().toISOString(),
      tool: input.tool,
      hook: "after",
      sessionId: input.sessionID,
      callId: input.callID,
      detections: allDetectionCategories.map((cat) => ({
        patternId: "regex",
        category: cat,
        confidence: "high" as const,
      })),
      blocked: llmBlocked,
      blockReason: llmBlocked ? "LLM sanitizer unreachable or failed — output blocked for safety" : undefined,
      redactedCount: outputActionMode === "pass" ? 0 : regexDetections,
      llmDetections: llmDetections > 0 ? llmDetections : undefined,
    })

    // Toast logic depends on action mode
    if (totalDetections > 0 && config.notifications) {
      if (outputActionMode === "warn") {
        // "warn" mode: always show detailed toast (bypass rate limiter)
        try {
          const parts: string[] = []
          if (regexDetections > 0) parts.push(`${regexDetections} by regex`)
          if (llmDetections > 0) parts.push(`${llmDetections} by LLM`)
          const categories = [...new Set(allDetectionCategories)].join(", ")
          await client.tui.showToast({
            body: {
              message: `🔒 Redacted ${totalDetections} secret(s) in ${input.tool} output (${parts.join(", ")}) [${categories}]`,
              variant: "warning" as const,
            },
          })
        } catch { /* toast failure is non-critical */ }
      } else if (outputActionMode === "pass") {
        // "pass" mode: log-only, show toast but indicate no redaction
        if (canToast(toastState)) {
          try {
            const categories = [...new Set(allDetectionCategories)].join(", ")
            await client.tui.showToast({
              body: {
                message: `⚠️ Detected ${totalDetections} secret(s) in ${input.tool} output (NOT redacted — pass mode) [${categories}]`,
                variant: "info" as const,
              },
            })
          } catch { /* toast failure is non-critical */ }
        }
      } else {
        // "redact" mode (default): rate-limited toast
        if (canToast(toastState)) {
          try {
            const parts: string[] = []
            if (regexDetections > 0) parts.push(`${regexDetections} by regex`)
            if (llmDetections > 0) parts.push(`${llmDetections} by LLM`)
            await client.tui.showToast({
              body: {
                message: `🔒 Redacted ${totalDetections} secret(s) in ${input.tool} output (${parts.join(", ")})`,
                variant: "warning" as const,
              },
            })
          } catch { /* toast failure is non-critical */ }
        }
      }
    }

    if (totalDetections === 0) {
      sessionStats.recordPass(input.tool)
    }

    diagnosticLogger?.hookEnd("output-redactor", input.tool, input.callID, Date.now() - hookStart, {
      outcome: llmBlocked ? "blocked" : totalDetections > 0 ? "redacted" : "pass",
      regexDetections: regexDetections,
      llmDetections,
    })
  }
}
