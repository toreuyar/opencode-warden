import type { SecurityGuardConfig } from "../types.js"
import { DEFAULT_TRIAGE_SYSTEM_PROMPT, buildTriagePrompt } from "./prompts.js"
import type { ProviderChain } from "./provider-chain.js"
import { tryParseJsonObject } from "../utils/json-repair.js"

export interface TriageResult {
  needsSanitization: boolean
  reason: string
}

export class OutputTriageEvaluator {
  private endpointConfig: SecurityGuardConfig["llm"]["outputTriage"]
  private debugLog?: (msg: string) => void
  private providerChain: ProviderChain
  private systemPrompt: string

  constructor(
    config: SecurityGuardConfig["llm"]["outputTriage"],
    providerChain: ProviderChain,
    debugLog?: (msg: string) => void,
  ) {
    this.endpointConfig = config
    this.debugLog = debugLog
    this.providerChain = providerChain
    this.systemPrompt =
      config.systemPrompt || DEFAULT_TRIAGE_SYSTEM_PROMPT
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
   * Evaluate whether a tool call's output needs full LLM sanitization.
   * Only receives tool name and args — never sees the output.
   * Fail-closed: any error returns needsSanitization=true.
   */
  async evaluate(
    tool: string,
    args: Record<string, unknown>,
  ): Promise<TriageResult> {
    const log = this.debugLog
    const start = Date.now()

    log?.(
      `Output triage: tool=${tool} args=${JSON.stringify(args).substring(0, 120)} → calling LLM...`,
    )

    const customTemplate = this.endpointConfig.promptTemplate || ""
    const prompt = buildTriagePrompt(tool, args, customTemplate || undefined)

    try {
      const response = await this.providerChain.call(
        [
          { role: "system", content: this.systemPrompt },
          { role: "user", content: prompt },
        ],
        { componentName: "output-triage" },
      )

      const result = this.parseResponse(response)

      log?.(
        `Output triage result: needsSanitization=${result.needsSanitization} reason="${result.reason}" (${Date.now() - start}ms)`,
      )

      return result
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err)
      log?.(
        `Output triage failed: ${errMsg} — fail-closed (throwing to block)`,
      )
      throw new Error(`Command triage failed: ${errMsg}`)
    }
  }

  private parseResponse(response: string): TriageResult {
    const parsed = tryParseJsonObject(response)
    if (parsed && typeof parsed.needsSanitization === "boolean") {
      return {
        needsSanitization: parsed.needsSanitization,
        reason: (parsed.reason as string) || "",
      }
    }

    this.debugLog?.(
      `Output triage: parse failed — fail-closed:\n${response.substring(0, 300)}`,
    )

    throw new Error("Could not parse command triage response — no valid JSON with needsSanitization field")
  }
}
