import { existsSync, readFileSync } from "fs"
import { join } from "path"
import { DEFAULT_CONFIG } from "./defaults.js"
import {
  securityGuardConfigSchema,
  type SecurityGuardUserConfig,
} from "./schema.js"
import type { SecurityGuardConfig } from "../types.js"

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function deepMerge(target: any, source: any): any {
  const result = { ...target }

  for (const key of Object.keys(source)) {
    const sourceVal = source[key]
    const targetVal = result[key]

    if (
      sourceVal !== null &&
      sourceVal !== undefined &&
      typeof sourceVal === "object" &&
      !Array.isArray(sourceVal) &&
      targetVal !== null &&
      targetVal !== undefined &&
      typeof targetVal === "object" &&
      !Array.isArray(targetVal)
    ) {
      result[key] = deepMerge(targetVal, sourceVal)
    } else if (sourceVal !== undefined) {
      result[key] = sourceVal
    }
  }

  return result
}

function loadConfigFile(
  configPath: string,
  warnings?: string[],
): SecurityGuardUserConfig | undefined {
  if (!existsSync(configPath)) return undefined

  try {
    const raw = readFileSync(configPath, "utf-8")
    const parsed = JSON.parse(raw)
    const validated = securityGuardConfigSchema.parse(parsed)
    return validated
  } catch (err) {
    warnings?.push(
      `Invalid config at ${configPath}: ${err instanceof Error ? err.message : err}`,
    )
    return undefined
  }
}

const LLM_ENDPOINT_KEYS = ['baseUrl', 'model', 'apiKey', 'timeout', 'temperature', 'headers', 'healthCheckPath', 'completionsPath'] as const
const LLM_COMPONENT_KEYS = ['safetyEvaluator', 'outputTriage', 'outputTextTriage', 'outputSanitizer'] as const

/**
 * Ensure a provider object has all required fields with safe defaults.
 * Applied to every provider during config resolution so the config
 * object fulfills its LlmProviderConfig type contract.
 */
function normalizeProviderObj(raw: Record<string, unknown>, index: number): Record<string, unknown> {
  return {
    name: raw.name || `provider-${index + 1}`,
    cooldown: raw.cooldown ?? 0,
    baseUrl: raw.baseUrl || "",
    model: raw.model || "",
    apiKey: raw.apiKey || "",
    timeout: raw.timeout || 0,
    temperature: raw.temperature ?? 0,
    headers: raw.headers || {},
    healthCheckPath: raw.healthCheckPath || "",
    completionsPath: raw.completionsPath || "",
  }
}

/**
 * Normalize all provider objects in an array.
 */
function normalizeProviders(arr: unknown[]): Record<string, unknown>[] {
  return arr.map((p, i) => normalizeProviderObj(p as Record<string, unknown>, i))
}

/**
 * Normalize flat endpoint fields into a single-element providers array.
 * Used for backward compatibility when a config section has flat fields
 * but no explicit `providers` array.
 */
function flatFieldsToProvider(obj: Record<string, unknown>): Record<string, unknown> | null {
  const provider: Record<string, unknown> = {}
  let hasAny = false
  for (const key of LLM_ENDPOINT_KEYS) {
    if (obj[key] !== undefined) {
      provider[key] = obj[key]
      hasAny = true
    }
  }
  if (!hasAny) return null
  provider.name = "default"
  provider.cooldown = 0
  return provider
}

/**
 * Pre-merge inheritance for provider chains and flat endpoint fields.
 *
 * Resolution order:
 * 1. If shared `llm.providers` exists → that's the inherited chain
 * 2. Else if shared flat endpoint fields exist → normalize into single-provider array
 * 3. For each component:
 *    a. If it has its own `providers` → use those (no inheritance)
 *    b. Else if it has flat endpoint fields → normalize into single-provider array
 *    c. Else → inherit the shared chain
 *
 * Also propagates flat endpoint fields into components for backward compat
 * (existing code still reads flat fields from the resolved config).
 */
function resolveLlmInheritance(userConfig: SecurityGuardUserConfig): void {
  if (!userConfig.llm) return
  const llm = userConfig.llm as Record<string, unknown>

  // ─── Determine shared provider chain ───
  let sharedProviders = llm.providers as unknown[] | undefined
  if (!sharedProviders || !Array.isArray(sharedProviders) || sharedProviders.length === 0) {
    // No explicit providers — try normalizing flat fields
    const fromFlat = flatFieldsToProvider(llm)
    if (fromFlat) {
      sharedProviders = normalizeProviders([fromFlat])
    } else {
      sharedProviders = undefined
    }
  } else {
    sharedProviders = normalizeProviders(sharedProviders)
  }

  // ─── Propagate flat endpoint fields into components (backward compat) ───
  const shared: Record<string, unknown> = {}
  for (const key of LLM_ENDPOINT_KEYS) {
    if (llm[key] !== undefined) shared[key] = llm[key]
  }

  for (const comp of LLM_COMPONENT_KEYS) {
    const compConfig = llm[comp] as Record<string, unknown> | undefined

    if (!compConfig) {
      // Component not in user config — create with shared values + inherited providers
      const stub: Record<string, unknown> = { ...shared }
      if (sharedProviders) {
        stub.providers = sharedProviders
      }
      llm[comp] = stub
    } else {
      // Component exists — fill missing flat endpoint fields
      for (const [key, value] of Object.entries(shared)) {
        if (compConfig[key] === undefined) {
          compConfig[key] = value
        }
      }

      // Resolve providers for this component
      const compProviders = compConfig.providers as unknown[] | undefined
      if (!compProviders || !Array.isArray(compProviders) || compProviders.length === 0) {
        // No explicit component providers — try flat fields, then inherit shared
        const fromFlat = flatFieldsToProvider(compConfig)
        if (fromFlat) {
          compConfig.providers = normalizeProviders([fromFlat])
        } else if (sharedProviders) {
          compConfig.providers = sharedProviders // Already normalized above
        }
      } else {
        compConfig.providers = normalizeProviders(compProviders)
      }
    }
  }
}

export interface LoadConfigOptions {
  /**
   * Skip loading global config from ~/.config/opencode/opencode-warden.json
   * Useful for tests to avoid interference from user's actual global config.
   */
  skipGlobalConfig?: boolean
}

export function loadConfig(
  projectDir: string,
  options?: LoadConfigOptions,
): { config: SecurityGuardConfig; warnings: string[] } {
  const warnings: string[] = []

  // Start with defaults
  let config: SecurityGuardConfig = structuredClone(DEFAULT_CONFIG)

  // Layer 1: Global config (can be skipped for tests)
  if (!options?.skipGlobalConfig) {
    const homeDir =
      process.env.HOME || process.env.USERPROFILE || "~"
    const globalConfigPath = join(
      homeDir,
      ".config",
      "opencode",
      "opencode-warden.json",
    )
    const globalConfig = loadConfigFile(globalConfigPath, warnings)
    if (globalConfig) {
      resolveLlmInheritance(globalConfig)
      config = deepMerge(config, globalConfig) as SecurityGuardConfig
    }
  }

  // Layer 2: Project config
  const projectConfigPath = join(
    projectDir,
    ".opencode",
    "opencode-warden.json",
  )
  const projectConfig = loadConfigFile(projectConfigPath, warnings)
  if (projectConfig) {
    resolveLlmInheritance(projectConfig)
    config = deepMerge(config, projectConfig) as SecurityGuardConfig
  }

  return { config, warnings }
}

export { DEFAULT_CONFIG } from "./defaults.js"
export { securityGuardConfigSchema } from "./schema.js"
export type { SecurityGuardUserConfig } from "./schema.js"
