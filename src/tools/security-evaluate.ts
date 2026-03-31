import type { SafetyEvaluator } from "../llm/safety-evaluator.js"

interface EvaluateDeps {
  safetyEvaluator: SafetyEvaluator | null
}

export function createSecurityEvaluateTool(deps: EvaluateDeps) {
  const { safetyEvaluator } = deps

  return {
    description:
      "Dry-run a command through safety evaluation without executing it",
    args: {
      tool: {
        type: "string" as const,
        description:
          'Tool name to evaluate (e.g., "bash", "write", "edit")',
      },
      command: {
        type: "string" as const,
        optional: true,
        description: "Command string (for bash tool)",
      },
      args: {
        type: "string" as const,
        optional: true,
        description: "JSON string of tool arguments (for non-bash tools)",
      },
    },
    async execute(execArgs: {
      tool: string
      command?: string
      args?: string
    }): Promise<string> {
      if (!safetyEvaluator) {
        return "Safety evaluator is not enabled. Enable LLM in your Warden configuration to use this tool."
      }

      // Build args object
      let toolArgs: Record<string, unknown>
      if (execArgs.tool === "bash" && execArgs.command) {
        toolArgs = { command: execArgs.command }
      } else if (execArgs.args) {
        try {
          toolArgs = JSON.parse(execArgs.args)
        } catch {
          return "Error: 'args' must be a valid JSON string."
        }
      } else if (execArgs.command) {
        toolArgs = { command: execArgs.command }
      } else {
        return "Error: provide 'command' (for bash) or 'args' (JSON string for other tools)."
      }

      try {
        const result = await safetyEvaluator.dryRun(execArgs.tool, toolArgs)

        const lines: string[] = []
        lines.push(`=== Safety Evaluation (dry-run) ===`)
        lines.push("")
        lines.push(`Tool: ${execArgs.tool}`)
        lines.push(`Safe: ${result.safe ? "Yes" : "No"}`)
        lines.push(`Risk Level: ${result.riskLevel}`)
        lines.push(`Recommendation: ${result.recommendation}`)

        if (result.riskDimensions.length > 0) {
          lines.push(`Risk Dimensions: ${result.riskDimensions.join(", ")}`)
        }

        lines.push(`Explanation: ${result.explanation}`)

        if (result.suggestedAlternative) {
          lines.push(`Suggested Alternative: ${result.suggestedAlternative}`)
        }

        return lines.join("\n")
      } catch (err) {
        return `Evaluation failed: ${err instanceof Error ? err.message : err}`
      }
    },
  }
}
