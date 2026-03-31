import type { SecurityGuardConfig } from "../types.js"
import { DEFAULT_TEXT_TRIAGE_SYSTEM_PROMPT, buildTextTriagePrompt } from "./prompts.js"
import type { ProviderChain } from "./provider-chain.js"
import { tryParseJsonObject } from "../utils/json-repair.js"

export interface TextTriageResult {
  needsSanitization: boolean
  reason: string
}

export class OutputTextTriageEvaluator {
  private endpointConfig: SecurityGuardConfig["llm"]["outputTextTriage"]
  private debugLog?: (msg: string) => void
  private providerChain: ProviderChain
  private systemPrompt: string

  constructor(
    config: SecurityGuardConfig["llm"]["outputTextTriage"],
    providerChain: ProviderChain,
    debugLog?: (msg: string) => void,
  ) {
    this.endpointConfig = config
    this.debugLog = debugLog
    this.providerChain = providerChain
    this.systemPrompt =
      config.systemPrompt || DEFAULT_TEXT_TRIAGE_SYSTEM_PROMPT
  }

  async healthCheck(): Promise<boolean> {
    return this.providerChain.healthCheck()
  }

  isAvailable(): boolean {
    return this.providerChain.isAvailable()
  }

  isEnabled(): boolean {
    return this.endpointConfig.enabled
  }

  /**
   * Evaluate whether actual output text contains secrets and needs sanitization.
   * Sees both the command context and the output text.
   * Fail-closed: any error returns needsSanitization=true.
   */
  async evaluate(
    tool: string,
    args: Record<string, unknown>,
    rawOutput: string,
  ): Promise<TextTriageResult> {
    const log = this.debugLog
    const start = Date.now()

    log?.(
      `Text triage: tool=${tool} outputLength=${rawOutput.length} → calling LLM...`,
    )

    const customTemplate = this.endpointConfig.promptTemplate || ""
    const prompt = buildTextTriagePrompt(tool, args, rawOutput, customTemplate || undefined)

    try {
      const response = await this.providerChain.call(
        [
          { role: "system", content: this.systemPrompt },
          { role: "user", content: prompt },
        ],
        { componentName: "output-text-triage" },
      )

      const result = this.parseResponse(response)

      log?.(
        `Text triage result: needsSanitization=${result.needsSanitization} reason="${result.reason}" (${Date.now() - start}ms)`,
      )

      return result
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err)
      log?.(
        `Text triage failed: ${errMsg} — fail-closed (throwing to block)`,
      )
      throw new Error(`Text triage failed: ${errMsg}`)
    }
  }

  private parseResponse(response: string): TextTriageResult {
    const parsed = tryParseJsonObject(response)
    if (parsed && typeof parsed.needsSanitization === "boolean") {
      return {
        needsSanitization: parsed.needsSanitization,
        reason: (parsed.reason as string) || "",
      }
    }

    this.debugLog?.(
      `Text triage: parse failed — fail-closed:\n${response.substring(0, 300)}`,
    )

    throw new Error("Could not parse text triage response — no valid JSON with needsSanitization field")
  }
}
