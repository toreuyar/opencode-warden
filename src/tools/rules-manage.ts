import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs"
import { join, dirname } from "path"
import type { DetectionEngine } from "../detection/engine.js"
import type { SecurityGuardConfig, CustomPatternConfig } from "../types.js"
import { getPatterns, getAllBuiltinPatterns } from "../detection/patterns/index.js"

interface RulesManageDeps {
  engine: DetectionEngine
  config: SecurityGuardConfig
  projectDir: string
}

export function createRulesManageTool(deps: RulesManageDeps) {
  const { engine, config, projectDir } = deps

  const configPath = join(projectDir, ".opencode", "opencode-warden.json")

  function readProjectConfig(): Record<string, unknown> {
    if (!existsSync(configPath)) return {}
    try {
      return JSON.parse(readFileSync(configPath, "utf-8"))
    } catch {
      return {}
    }
  }

  function writeProjectConfig(data: Record<string, unknown>): void {
    const dir = dirname(configPath)
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true })
    }
    writeFileSync(configPath, JSON.stringify(data, null, 2) + "\n", "utf-8")
  }

  function reloadEngine(): void {
    const patterns = getPatterns(
      config.categories,
      config.disabledPatterns,
      config.customPatterns,
    )
    engine.setPatterns(patterns)
  }

  return {
    description:
      "Manage custom security detection rules — list active rules, test patterns against sample strings, add new rules, or remove existing ones",
    args: {
      action: {
        type: "string" as const,
        description:
          'Action: "list", "test", "add", or "remove"',
      },
      pattern: {
        type: "string" as const,
        optional: true,
        description: "Regex pattern string (for test/add)",
      },
      testString: {
        type: "string" as const,
        optional: true,
        description: "Sample string to test against (for test)",
      },
      name: {
        type: "string" as const,
        optional: true,
        description: "Rule name (for add)",
      },
      category: {
        type: "string" as const,
        optional: true,
        description: "Category (for add)",
      },
      id: {
        type: "string" as const,
        optional: true,
        description: "Rule ID (for remove)",
      },
      redactTemplate: {
        type: "string" as const,
        optional: true,
        description: "Redaction template (for add, default: '****')",
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
          const customPatterns = config.customPatterns

          const lines: string[] = []
          lines.push(`=== Active Security Rules ===`)
          lines.push("")
          lines.push(`Built-in rules: ${builtinPatterns.length}`)
          lines.push(`Custom rules: ${customPatterns.length}`)
          lines.push(`Disabled rules: ${config.disabledPatterns.length}`)
          lines.push("")

          lines.push("--- Built-in Rules ---")
          for (const p of builtinPatterns) {
            const disabled = config.disabledPatterns.includes(p.id)
            const catEnabled = config.categories[p.category]
            const status =
              disabled ? "DISABLED" : !catEnabled ? "CAT-OFF" : "ACTIVE"
            lines.push(
              `  [${status}] ${p.id} | ${p.name} | ${p.category} | ${p.confidence}`,
            )
          }

          if (customPatterns.length > 0) {
            lines.push("")
            lines.push("--- Custom Rules ---")
            for (const p of customPatterns) {
              lines.push(
                `  ${p.id} | ${p.name} | ${p.category} | /${p.pattern}/ → "${p.redactTemplate}"`,
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
          if (!args.id && !args.name) return "Error: 'id' or 'name' is required."

          // Validate regex compiles
          try {
            new RegExp(args.pattern, "g")
          } catch (err) {
            return `Error: Invalid regex pattern: ${err instanceof Error ? err.message : err}`
          }

          const id =
            args.id ||
            args.name
              .toLowerCase()
              .replace(/[^a-z0-9]+/g, "-")
              .replace(/^-|-$/g, "")

          // Check for duplicate ID
          if (config.customPatterns.some((p) => p.id === id)) {
            return `Error: A custom pattern with ID "${id}" already exists.`
          }

          const newPattern: CustomPatternConfig = {
            id,
            name: args.name,
            category: (args.category as CustomPatternConfig["category"]) || "api-keys",
            pattern: args.pattern,
            redactTemplate: args.redactTemplate || "****",
            confidence: "high",
          }

          // Add to in-memory config
          config.customPatterns.push(newPattern)

          // Persist to config file
          const projectCfg = readProjectConfig()
          if (!Array.isArray(projectCfg.customPatterns)) {
            projectCfg.customPatterns = []
          }
          ;(projectCfg.customPatterns as CustomPatternConfig[]).push(newPattern)
          writeProjectConfig(projectCfg)

          // Reload detection engine
          reloadEngine()

          return [
            `Added custom rule "${args.name}" (${id}).`,
            `  Category: ${newPattern.category}`,
            `  Pattern: /${args.pattern}/g`,
            `  Redact: "${newPattern.redactTemplate}"`,
            `  Persisted to ${configPath}`,
            `  Detection engine reloaded.`,
          ].join("\n")
        }

        case "remove": {
          if (!args.id) return "Error: 'id' is required for the 'remove' action."

          // Check if it's a built-in pattern
          const isBuiltin = getAllBuiltinPatterns().some((p) => p.id === args.id)
          if (isBuiltin) {
            return (
              `"${args.id}" is a built-in pattern and cannot be removed. ` +
              `To disable it, add it to the "disabledPatterns" array in your config.`
            )
          }

          // Check if it exists as a custom pattern
          const idx = config.customPatterns.findIndex((p) => p.id === args.id)
          if (idx === -1) {
            return `Custom pattern "${args.id}" not found.`
          }

          // Remove from in-memory config
          config.customPatterns.splice(idx, 1)

          // Persist to config file
          const projectCfg = readProjectConfig()
          if (Array.isArray(projectCfg.customPatterns)) {
            projectCfg.customPatterns = (
              projectCfg.customPatterns as CustomPatternConfig[]
            ).filter((p) => p.id !== args.id)
          }
          writeProjectConfig(projectCfg)

          // Reload detection engine
          reloadEngine()

          return `Removed custom pattern "${args.id}". Detection engine reloaded.`
        }

        default:
          return `Unknown action: "${args.action}". Use "list", "test", "add", or "remove".`
      }
    },
  }
}
