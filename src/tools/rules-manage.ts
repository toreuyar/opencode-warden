import type { DetectionEngine } from "../detection/engine.js"
import type { SecurityGuardConfig, CustomPatternConfig, DetectionPattern } from "../types.js"
import { getPatterns, getAllBuiltinPatterns } from "../detection/patterns/index.js"

interface RulesManageDeps {
  engine: DetectionEngine
  config: SecurityGuardConfig
  projectDir: string
}

/**
 * AI-managed pattern registry.
 *
 * Three-layer pattern architecture:
 *   Layer 1 — Built-in:  Hardcoded, immutable, cannot be altered at runtime.
 *   Layer 2 — User:      Defined in config files, immutable at runtime.
 *   Layer 3 — AI:        Managed here, session-only, not persisted to config.
 *
 * The AI can freely add/remove/edit its own patterns (Layer 3) but cannot
 * touch Layer 1 or Layer 2 patterns.
 */
const aiPatterns: DetectionPattern[] = []

export function getAiPatterns(): DetectionPattern[] {
  return aiPatterns
}

export function createRulesManageTool(deps: RulesManageDeps) {
  const { engine, config } = deps

  function reloadEngine(): void {
    const patterns = getPatterns(
      config.categories,
      config.disabledPatterns,
      config.customPatterns,
      undefined,
      aiPatterns,
    )
    engine.setPatterns(patterns)
  }

  return {
    description:
      "Manage security detection rules — list all active rules across all layers, test patterns against sample strings, and add/edit/remove AI-managed rules (session-only, not persisted to config)",
    args: {
      action: {
        type: "string" as const,
        description:
          'Action: "list", "test", "add", "edit", or "remove"',
      },
      pattern: {
        type: "string" as const,
        optional: true,
        description: "Regex pattern string (for test/add/edit)",
      },
      testString: {
        type: "string" as const,
        optional: true,
        description: "Sample string to test against (for test)",
      },
      name: {
        type: "string" as const,
        optional: true,
        description: "Rule name (for add/edit)",
      },
      category: {
        type: "string" as const,
        optional: true,
        description: "Category (for add/edit)",
      },
      id: {
        type: "string" as const,
        optional: true,
        description: "Rule ID (for edit/remove)",
      },
      redactTemplate: {
        type: "string" as const,
        optional: true,
        description: "Redaction template (for add/edit, default: '****')",
      },
    },
    async execute(args: {
      action: string
      pattern?: string
      testString?: string
      name?: string
      category?: string
      id?: string
      redactTemplate?: string
    }): Promise<string> {
      switch (args.action) {
        case "list": {
          const builtinPatterns = getAllBuiltinPatterns()
          const userPatterns = config.customPatterns

          const lines: string[] = []
          lines.push(`=== Security Detection Rules ===`)
          lines.push("")
          lines.push(`Layer 1 — Built-in rules: ${builtinPatterns.length} (immutable)`)
          lines.push(`Layer 2 — User rules: ${userPatterns.length} (config-managed, immutable at runtime)`)
          lines.push(`Layer 3 — AI rules: ${aiPatterns.length} (session-only)`)
          lines.push(`Disabled patterns: ${config.disabledPatterns.length}`)
          lines.push("")

          lines.push("--- Layer 1: Built-in Rules ---")
          for (const p of builtinPatterns) {
            const disabled = config.disabledPatterns.includes(p.id)
            const catEnabled = config.categories[p.category]
            const status =
              disabled ? "DISABLED" : !catEnabled ? "CAT-OFF" : "ACTIVE"
            lines.push(
              `  [${status}] ${p.id} | ${p.name} | ${p.category} | ${p.confidence}`,
            )
          }

          if (userPatterns.length > 0) {
            lines.push("")
            lines.push("--- Layer 2: User Rules (from config) ---")
            for (const p of userPatterns) {
              lines.push(
                `  ${p.id} | ${p.name} | ${p.category} | /${p.pattern}/ → "${p.redactTemplate}"`,
              )
            }
          }

          if (aiPatterns.length > 0) {
            lines.push("")
            lines.push("--- Layer 3: AI Rules (session-only) ---")
            for (const p of aiPatterns) {
              lines.push(
                `  ${p.id} | ${p.name} | ${p.category} | /${p.pattern.source}/ → ${p.confidence}`,
              )
            }
          }

          return lines.join("\n")
        }

        case "test": {
          if (!args.pattern) {
            return "Error: 'pattern' is required for the 'test' action."
          }
          if (!args.testString) {
            return "Error: 'testString' is required for the 'test' action."
          }

          try {
            const regex = new RegExp(args.pattern, "g")
            const matches: string[] = []
            let match: RegExpExecArray | null
            while ((match = regex.exec(args.testString)) !== null) {
              matches.push(
                `  Match: "${match[0]}" at index ${match.index}`,
              )
            }

            if (matches.length === 0) {
              return `Pattern /${args.pattern}/g did not match the test string.`
            }

            const redactTemplate = args.redactTemplate || "****"
            const redacted = args.testString.replace(
              new RegExp(args.pattern, "g"),
              redactTemplate,
            )

            return [
              `Pattern /${args.pattern}/g matched ${matches.length} time(s):`,
              ...matches,
              "",
              `After redaction (→ "${redactTemplate}"):`,
              `  ${redacted}`,
            ].join("\n")
          } catch (err) {
            return `Error: Invalid regex pattern: ${err instanceof Error ? err.message : err}`
          }
        }

        case "add": {
          if (!args.pattern) return "Error: 'pattern' is required."
          if (!args.name) return "Error: 'name' is required."

          // Validate regex compiles
          try {
            new RegExp(args.pattern, "g")
          } catch (err) {
            return `Error: Invalid regex pattern: ${err instanceof Error ? err.message : err}`
          }

          const rawId =
            args.id ||
            args.name
              .toLowerCase()
              .replace(/[^a-z0-9]+/g, "-")
              .replace(/^-|-$/g, "")
          const id = rawId.startsWith("ai-") ? rawId : "ai-" + rawId

          // Check for duplicate ID across all layers
          const allBuiltin = getAllBuiltinPatterns()
          if (allBuiltin.some((p) => p.id === id)) {
            return `Error: ID "${id}" conflicts with a built-in pattern.`
          }
          if (config.customPatterns.some((p) => p.id === id)) {
            return `Error: ID "${id}" conflicts with a user-configured pattern.`
          }
          if (aiPatterns.some((p) => p.id === id)) {
            return `Error: An AI pattern with ID "${id}" already exists. Use "edit" to modify it.`
          }

          const newPattern: DetectionPattern = {
            id,
            name: args.name,
            category: (args.category as CustomPatternConfig["category"]) || "api-keys",
            pattern: new RegExp(args.pattern, "g"),
            redact: () => args.redactTemplate || "****",
            confidence: "high",
            source: "ai",
          }

          aiPatterns.push(newPattern)
          reloadEngine()

          return [
            `Added AI rule "${args.name}" (${id}).`,
            `  Category: ${newPattern.category}`,
            `  Pattern: /${args.pattern}/g`,
            `  Redact: "${args.redactTemplate || "****"}"`,
            `  Scope: session-only (not persisted to config)`,
            `  Detection engine reloaded.`,
          ].join("\n")
        }

        case "edit": {
          if (!args.id) return "Error: 'id' is required for the 'edit' action."

          // Check if it's a built-in or user pattern
          const allBuiltin = getAllBuiltinPatterns()
          if (allBuiltin.some((p) => p.id === args.id)) {
            return `Error: "${args.id}" is a built-in pattern (Layer 1) and cannot be edited.`
          }
          if (config.customPatterns.some((p) => p.id === args.id)) {
            return `Error: "${args.id}" is a user-configured pattern (Layer 2) and cannot be edited at runtime. Modify the config file instead.`
          }

          const idx = aiPatterns.findIndex((p) => p.id === args.id)
          if (idx === -1) {
            return `Error: AI pattern "${args.id}" not found.`
          }

          const existing = aiPatterns[idx]

          if (args.pattern) {
            try {
              existing.pattern = new RegExp(args.pattern, "g")
            } catch (err) {
              return `Error: Invalid regex pattern: ${err instanceof Error ? err.message : err}`
            }
          }
          if (args.name) existing.name = args.name
          if (args.category) existing.category = args.category as CustomPatternConfig["category"]
          if (args.redactTemplate) existing.redact = () => args.redactTemplate!

          reloadEngine()

          return [
            `Updated AI rule "${existing.id}".`,
            `  Name: ${existing.name}`,
            `  Pattern: /${existing.pattern.source}/g`,
            `  Category: ${existing.category}`,
            `  Detection engine reloaded.`,
          ].join("\n")
        }

        case "remove": {
          if (!args.id) return "Error: 'id' is required for the 'remove' action."

          // Check if it's a built-in or user pattern
          const allBuiltin = getAllBuiltinPatterns()
          if (allBuiltin.some((p) => p.id === args.id)) {
            return `Error: "${args.id}" is a built-in pattern (Layer 1) and cannot be removed.`
          }
          if (config.customPatterns.some((p) => p.id === args.id)) {
            return `Error: "${args.id}" is a user-configured pattern (Layer 2) and cannot be removed at runtime. Modify the config file instead.`
          }

          const idx = aiPatterns.findIndex((p) => p.id === args.id)
          if (idx === -1) {
            return `AI pattern "${args.id}" not found.`
          }

          aiPatterns.splice(idx, 1)
          reloadEngine()

          return `Removed AI pattern "${args.id}". Detection engine reloaded.`
        }

        default:
          return `Unknown action: "${args.action}". Use "list", "test", "add", "edit", or "remove".`
      }
    },
  }
}
