import type {
  SafetyEvaluation,
  RiskLevel,
  SecurityGuardConfig,
} from "../types.js"
import { ConversationContext } from "./context.js"
import {
  DEFAULT_SAFETY_SYSTEM_PROMPT,
  DEFAULT_FILE_EXECUTION_SYSTEM_PROMPT,
  buildSafetyPrompt,
  buildFileExecutionPrompt,
} from "./prompts.js"
import type { ProviderChain } from "./provider-chain.js"
import { parseSshCommand } from "../utils/ssh.js"
import { resolveAllowedPatterns } from "../config/profiles.js"
import {
  compileCommandPattern,
  hasDangerousMetachars,
  isAllowedOperation,
  isPipedCommandSafe,
  stripSudo,
} from "../utils/command-patterns.js"
import { tryParseJsonObject } from "../utils/json-repair.js"

const RISK_LEVEL_ORDER: Record<RiskLevel, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

export class SafetyEvaluator {
  private context: ConversationContext
  private config: SecurityGuardConfig["llm"]["safetyEvaluator"]
  private indirectExecutionConfig?: SecurityGuardConfig["indirectExecution"]
  private debugLog?: (msg: string) => void
  private providerChain: ProviderChain
  private compiledPatterns: RegExp[]
  private resolvedPatterns: string[]

  constructor(
    llmConfig: SecurityGuardConfig["llm"],
    providerChain: ProviderChain,
    debugLog?: (msg: string) => void,
    indirectExecutionConfig?: SecurityGuardConfig["indirectExecution"],
  ) {
    this.config = llmConfig.safetyEvaluator
    this.indirectExecutionConfig = indirectExecutionConfig
    this.debugLog = debugLog
    this.providerChain = providerChain

    // Resolve and compile allowed operation patterns once at construction time
    this.resolvedPatterns = resolveAllowedPatterns(
      this.config.allowedOperations,
      this.config.operationalProfiles,
    )
    this.compiledPatterns = this.resolvedPatterns.map(compileCommandPattern)

    const systemPrompt =
      this.config.systemPrompt || DEFAULT_SAFETY_SYSTEM_PROMPT
    this.context = new ConversationContext({
      systemPrompt,
      accumulate: llmConfig.contextAccumulation,
      detectionsOnly: llmConfig.contextDetectionsOnly,
      maxPairs: llmConfig.maxContextPairs,
      maxChars: llmConfig.maxContextChars,
    })
  }

  /**
   * Check if this command can bypass LLM evaluation.
   *
   * Evaluation pipeline:
   * 1. Extract command
   * 2. Has dangerous metacharacters? → go to LLM (return false)
   * 3. Has pipes? → split and check each segment
   * 4. Simple command → check prefix bypass, then pattern match
   * 5. Parse as SSH → repeat steps 2-4 on inner command
   *    (SCP/SFTP/interactive SSH never bypassed)
   */
  isBypassed(tool: string, args: Record<string, unknown>): boolean {
    if (tool !== "bash") return false

    const command = (args.command as string | undefined) || ""

    if (this.isCommandBypassed(command)) {
      this.debugLog?.(
        `Safety eval: tool=${tool} args=${JSON.stringify(args).substring(0, 120)} → BYPASSED`,
      )
      return true
    }

    // Check if it's an SSH command with a safe inner command
    const parsed = parseSshCommand(command)
    if (parsed) {
      if (parsed.type !== "ssh" || !parsed.innerCommand) return false
      if (this.isCommandBypassed(parsed.innerCommand)) {
        this.debugLog?.(
          `Safety eval: tool=${tool} args=${JSON.stringify(args).substring(0, 120)} → SSH INNER COMMAND BYPASSED`,
        )
        return true
      }
    }

    return false
  }

  /**
   * Check if a single command string (or SSH inner command) can bypass LLM.
   */
  private isCommandBypassed(command: string): boolean {
    // Step 1b: Strip leading sudo prefix before all checks
    const stripped = stripSudo(command)

    // Step 2: Dangerous metacharacters → always go to LLM
    if (hasDangerousMetachars(stripped)) return false

    // Step 3: Pipe chains
    if (stripped.includes("|")) {
      return isPipedCommandSafe(
        stripped,
        this.config.bypassedCommands,
        this.compiledPatterns,
      )
    }

    // Step 4: Simple command — check prefix bypass
    const trimmed = stripped.trimStart()
    if (
      this.config.bypassedCommands.some((prefix) =>
        trimmed.startsWith(prefix),
      )
    ) {
      return true
    }

    // Step 4b: Check against allowed operation patterns
    return isAllowedOperation(stripped, this.compiledPatterns)
  }

  /**
   * Check if this tool should be evaluated.
   */
  shouldEvaluate(tool: string): boolean {
    return this.config.enabled && this.config.tools.includes(tool)
  }

  /**
   * Evaluate a tool call for safety risks using the LLM.
   */
  async evaluate(
    tool: string,
    args: Record<string, unknown>,
  ): Promise<SafetyEvaluation> {
    const log = this.debugLog
    const start = Date.now()

    log?.(
      `Safety eval: tool=${tool} args=${JSON.stringify(args).substring(0, 120)} → calling LLM...`,
    )

    const customTemplate = this.config.promptTemplate || ""
    const prompt = buildSafetyPrompt(
      tool,
      args,
      customTemplate || undefined,
      this.config.operationalProfiles,
    )
    this.context.addUserMessage(prompt)

    try {
      const response = await this.providerChain.call(
        this.context.getMessages(),
        { componentName: "safety-evaluator" },
      )
      const evaluation = this.parseResponse(response)
      const result = this.applyThresholds(evaluation)
      this.context.addAssistantMessage(response, result.recommendation !== "allow")

      log?.(
        `Safety eval result: riskLevel=${result.riskLevel} recommendation=${result.recommendation} (${Date.now() - start}ms)\nPARSED RESULT:\n${JSON.stringify(result, null, 2)}`,
      )

      return result
    } catch (err) {
      this.debugLog?.(
        `Safety evaluation failed: ${err instanceof Error ? err.message : err}`,
      )
      // Fail closed: block if LLM is unreachable
      return {
        safe: false,
        riskLevel: "critical",
        riskDimensions: [],
        explanation: "LLM unreachable — blocking for safety",
        suggestedAlternative: "",
        recommendation: "block",
      }
    }
  }

  /**
   * Dry-run a tool call through safety evaluation WITHOUT modifying conversation context.
   * Used by the security_evaluate tool to let the AI pre-check commands.
   */
  async dryRun(
    tool: string,
    args: Record<string, unknown>,
  ): Promise<SafetyEvaluation> {
    const log = this.debugLog

    // Fast-path: bypassed commands don't need LLM
    if (this.isBypassed(tool, args)) {
      return {
        safe: true,
        riskLevel: "none",
        riskDimensions: [],
        explanation: "Pre-approved (bypassed command)",
        suggestedAlternative: "",
        recommendation: "allow",
      }
    }

    log?.(`Safety dry-run: tool=${tool} args=${JSON.stringify(args).substring(0, 120)}`)

    const systemPrompt = this.config.systemPrompt || DEFAULT_SAFETY_SYSTEM_PROMPT
    const customTemplate = this.config.promptTemplate || ""
    const prompt = buildSafetyPrompt(
      tool,
      args,
      customTemplate || undefined,
      this.config.operationalProfiles,
    )

    // One-shot messages — does NOT touch this.context
    const messages = [
      { role: "system" as const, content: systemPrompt },
      { role: "user" as const, content: prompt },
    ]

    try {
      const response = await this.providerChain.call(
        messages,
        { componentName: "safety-evaluator-dryrun" },
      )
      const evaluation = this.parseResponse(response)
      const result = this.applyThresholds(evaluation)

      log?.(
        `Safety dry-run result: riskLevel=${result.riskLevel} recommendation=${result.recommendation}`,
      )

      return result
    } catch (err) {
      log?.(`Safety dry-run failed: ${err instanceof Error ? err.message : err}`)
      return {
        safe: false,
        riskLevel: "critical",
        riskDimensions: [],
        explanation: "LLM unreachable — dry-run cannot evaluate",
        suggestedAlternative: "",
        recommendation: "block",
      }
    }
  }

  /**
   * Evaluate file content before execution (Layer 2: Indirect Execution Prevention).
   *
   * Stateless — does NOT use conversation context. File content provides all context.
   * Uses a dedicated system prompt optimized for file content analysis.
   * Fail-closed: returns block on any error.
   */
  async evaluateFileExecution(
    command: string,
    filePath: string,
    fileContent: string,
    writtenByAgent: boolean,
  ): Promise<SafetyEvaluation> {
    const log = this.debugLog
    const start = Date.now()

    const origin = writtenByAgent
      ? "WRITTEN BY AGENT in current session (elevated suspicion)"
      : "Pre-existing file (not written by agent)"

    log?.(
      `File execution eval: command="${command.substring(0, 80)}" file="${filePath}" origin="${origin}" contentLength=${fileContent.length} → calling LLM...`,
    )

    const prompt = buildFileExecutionPrompt(command, filePath, fileContent, origin, this.config.operationalProfiles, this.indirectExecutionConfig?.promptTemplate)

    const systemPrompt = this.indirectExecutionConfig?.systemPrompt || DEFAULT_FILE_EXECUTION_SYSTEM_PROMPT
    const messages = [
      { role: "system" as const, content: systemPrompt },
      { role: "user" as const, content: prompt },
    ]

    try {
      const response = await this.providerChain.call(
        messages,
        { componentName: "file-execution-evaluator" },
      )

      const evaluation = this.parseResponse(response)
      const result = this.applyThresholds(evaluation)

      log?.(
        `File execution eval result: riskLevel=${result.riskLevel} recommendation=${result.recommendation} (${Date.now() - start}ms)\nPARSED RESULT:\n${JSON.stringify(result, null, 2)}`,
      )

      return result
    } catch (err) {
      log?.(
        `File execution evaluation failed: ${err instanceof Error ? err.message : err}`,
      )
      // Fail closed
      return {
        safe: false,
        riskLevel: "critical",
        riskDimensions: [],
        explanation: "File content evaluation failed — blocking for safety",
        suggestedAlternative: "",
        recommendation: "block",
      }
    }
  }

  reset(): void {
    this.context.reset()
  }

  private applyThresholds(evaluation: SafetyEvaluation): SafetyEvaluation {
    const riskOrder = RISK_LEVEL_ORDER[evaluation.riskLevel] || 0
    const blockOrder = RISK_LEVEL_ORDER[this.config.blockThreshold] || 3
    const warnOrder = RISK_LEVEL_ORDER[this.config.warnThreshold] || 2

    if (riskOrder >= blockOrder) {
      return { ...evaluation, recommendation: "block", safe: false }
    }
    if (riskOrder >= warnOrder) {
      return { ...evaluation, recommendation: "warn", safe: true }
    }
    return { ...evaluation, recommendation: "allow", safe: true }
  }

  private parseResponse(response: string): SafetyEvaluation {
    // Try parsing with JSON repair (handles unescaped quotes from small LLMs)
    const parsed = tryParseJsonObject(response)
    if (parsed) {
      return {
        safe: Boolean(parsed.safe),
        riskLevel: ((parsed.riskLevel as string) || "none") as RiskLevel,
        riskDimensions: Array.isArray(parsed.riskDimensions)
          ? parsed.riskDimensions
          : [],
        explanation: (parsed.explanation as string) || "",
        suggestedAlternative: (parsed.suggestedAlternative as string) || "",
        recommendation: ((parsed.recommendation as string) || "allow") as SafetyEvaluation["recommendation"],
      }
    }

    this.debugLog?.(
      `Safety eval: JSON repair failed — could not parse response:\n${response.substring(0, 500)}`,
    )

    // If all parsing attempts fail, block for safety
    return {
      safe: false,
      riskLevel: "critical",
      riskDimensions: [],
      explanation: "Could not parse safety evaluation — blocking for safety",
      suggestedAlternative: "",
      recommendation: "block",
    }
  }
}
