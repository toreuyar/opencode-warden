import type { LlmSanitizeResult, LlmSanitizeFinding, SecurityGuardConfig } from "../types.js"
import { ConversationContext } from "./context.js"
import {
  DEFAULT_SANITIZER_SYSTEM_PROMPT,
  buildSanitizePrompt,
} from "./prompts.js"
import type { ProviderChain } from "./provider-chain.js"
import { tryParseJsonObject } from "../utils/json-repair.js"

export class LlmSanitizer {
  private context: ConversationContext
  private endpointConfig: SecurityGuardConfig["llm"]["outputSanitizer"]
  private llmEnabled: boolean
  private debugLog?: (msg: string) => void
  private providerChain: ProviderChain

  constructor(
    config: SecurityGuardConfig["llm"],
    providerChain: ProviderChain,
    debugLog?: (msg: string) => void,
  ) {
    this.endpointConfig = config.outputSanitizer
    this.llmEnabled = config.enabled
    this.debugLog = debugLog
    this.providerChain = providerChain
    const systemPrompt =
      config.outputSanitizer.systemPrompt || DEFAULT_SANITIZER_SYSTEM_PROMPT
    this.context = new ConversationContext({
      systemPrompt,
      accumulate: config.contextAccumulation,
      detectionsOnly: config.contextDetectionsOnly,
      maxPairs: config.maxContextPairs,
      maxChars: config.maxContextChars,
    })
  }

  /**
   * Check if at least one LLM provider is reachable.
   */
  async healthCheck(): Promise<boolean> {
    return this.providerChain.healthCheck()
  }

  /**
   * Returns true if at least one provider is available (not all on cooldown).
   */
  isAvailable(): boolean {
    return this.providerChain.isAvailable()
  }

  /**
   * Get the provider chain for dashboard/status display.
   */
  getProviderChain(): ProviderChain {
    return this.providerChain
  }

  /**
   * Check if this tool's output should be LLM-sanitized.
   */
  shouldSanitize(tool: string): boolean {
    return (
      this.llmEnabled &&
      this.endpointConfig.enabled &&
      this.endpointConfig.tools.includes(tool)
    )
  }

  /**
   * Sanitize tool output using the LLM (second pass after regex).
   */
  async sanitize(
    toolName: string,
    rawOutput: string,
    context?: string,
  ): Promise<LlmSanitizeResult> {
    const log = this.debugLog
    const start = Date.now()

    log?.(
      `Output sanitizer: tool=${toolName} outputLength=${rawOutput.length} context="${context || toolName}" → calling LLM...`,
    )

    const customTemplate = this.endpointConfig.promptTemplate || ""
    const prompt = buildSanitizePrompt(
      toolName,
      rawOutput,
      customTemplate || undefined,
      context,
    )
    this.context.addUserMessage(prompt)

    // Step 1: Network call via provider chain (handles fallback internally)
    let response: string
    try {
      response = await this.providerChain.call(
        this.context.getMessages(),
        { componentName: "output-sanitizer" },
      )
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err)
      const isTimeout = errMsg.includes("timed out") || errMsg.includes("aborted") || errMsg.includes("AbortError")
      log?.(
        `LLM sanitization ${isTimeout ? "timed out" : "network error"}: ${errMsg}`,
      )
      throw new Error(
        `LLM sanitization ${isTimeout ? "timed out" : "failed"}: ${errMsg}`,
      )
    }

    // Step 2: Parse response — errors here do NOT affect connection state
    // The LLM responded successfully but the output may not be parseable
    try {
      const result = this.parseResponse(response)
      this.context.addAssistantMessage(response, result.findings.length > 0)

      log?.(
        `Output sanitizer result: needsSanitization=${result.needsSanitization} ${result.findings.length} finding(s) (${Date.now() - start}ms)\nPARSED RESULT:\n${JSON.stringify(result, null, 2)}`,
      )

      return result
    } catch (parseErr) {
      // Parse failure — LLM is reachable but produced unparseable output
      // Do NOT set connected=false — this is a content issue, not a connectivity issue
      const parseMsg = parseErr instanceof Error ? parseErr.message : String(parseErr)
      log?.(
        `Output sanitizer: PARSE ERROR after successful LLM call (${Date.now() - start}ms): ${parseMsg}\nRAW RESPONSE:\n${response.substring(0, 500)}`,
      )
      // Fail closed: callers must handle this as a block, but LLM stays "connected"
      throw new Error(`LLM response parsing failed: ${parseMsg}`)
    }
  }

  reset(): void {
    this.context.reset()
  }

  private parseResponse(response: string): LlmSanitizeResult {
    // Try parsing with JSON repair (handles unescaped quotes from small LLMs)
    const parsed = tryParseJsonObject(response)
    if (!parsed) {
      throw new Error("Could not parse LLM sanitization response — no JSON found")
    }
    if (typeof parsed.needsSanitization !== "boolean") {
      throw new Error("Could not parse LLM sanitization response — missing needsSanitization field")
    }

    const findings: LlmSanitizeFinding[] = Array.isArray(parsed.findings)
      ? parsed.findings.filter(
          (f: Record<string, unknown>) =>
            typeof f.sensitive === "string" && f.sensitive.length > 0,
        )
      : []

    // Consistency check: needsSanitization=true but no findings → fail closed
    if (parsed.needsSanitization && findings.length === 0) {
      throw new Error(
        "LLM inconsistency: needsSanitization=true but findings is empty — fail closed",
      )
    }

    return {
      needsSanitization: parsed.needsSanitization as boolean,
      findings,
    }
  }
}

export { SafetyEvaluator } from "./safety-evaluator.js"
export { OutputTriageEvaluator } from "./output-triage.js"
export type { TriageResult } from "./output-triage.js"
export { OutputTextTriageEvaluator } from "./output-text-triage.js"
export type { TextTriageResult } from "./output-text-triage.js"
export { ProviderChain } from "./provider-chain.js"
export { ConversationContext } from "./context.js"
export { callLlm, checkLlmHealth, buildLlmHeaders, LlmApiError } from "./client.js"
export {
  SANITIZER_SYSTEM_PROMPT,
  SAFETY_SYSTEM_PROMPT,
  DEFAULT_SANITIZER_SYSTEM_PROMPT,
  DEFAULT_SAFETY_SYSTEM_PROMPT,
  DEFAULT_SANITIZER_PROMPT_TEMPLATE,
  DEFAULT_SAFETY_PROMPT_TEMPLATE,
  DEFAULT_TRIAGE_SYSTEM_PROMPT,
  DEFAULT_TRIAGE_PROMPT_TEMPLATE,
  DEFAULT_TEXT_TRIAGE_SYSTEM_PROMPT,
  DEFAULT_TEXT_TRIAGE_PROMPT_TEMPLATE,
  DEFAULT_FILE_EXECUTION_SYSTEM_PROMPT,
  DEFAULT_FILE_EXECUTION_PROMPT_TEMPLATE,
  renderTemplate,
  buildSanitizePrompt,
  buildSafetyPrompt,
  buildTriagePrompt,
  buildTextTriagePrompt,
  buildFileExecutionPrompt,
} from "./prompts.js"
