import { lstatSync, readFileSync } from "fs"
import { join } from "path"
import type { ZodIssue } from "zod"
import { DEFAULT_CONFIG } from "./defaults.js"
import {
  securityGuardConfigSchema,
  type SecurityGuardUserConfig,
} from "./schema.js"
import type {
  ConfigLoadFailure,
  ConfigSource,
  ConfigValidationIssue,
  LoadConfigResult,
  SecurityGuardConfig,
} from "../types.js"
import { normalizeToolList } from "../utils/tool-compat.js"

export type {
  ConfigFailureKind,
  ConfigLoadFailure,
  ConfigSource,
  ConfigValidationIssue,
  LoadConfigResult,
} from "../types.js"

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

interface LoadedConfigSource {
  config?: SecurityGuardUserConfig
  failure?: ConfigLoadFailure
}

function errnoCode(err: unknown): string | undefined {
  if (!err || typeof err !== "object" || !("code" in err)) return undefined
  const code = (err as { code?: unknown }).code
  return typeof code === "string" ? code : undefined
}

/**
 * Return true when a config path has a directory entry. Only ENOENT proves
 * absence: lstat() succeeds for a dangling symlink (the symlink exists even
 * though its target does not), and every other probe error means we cannot
 * safely conclude the user did not configure this layer.
 */
function configPathExists(configPath: string): boolean {
  try {
    lstatSync(configPath)
    return true
  } catch (err) {
    return errnoCode(err) !== "ENOENT"
  }
}

function describeZodIssue(issue: ZodIssue): ConfigValidationIssue {
  const path = issue.path.map((segment) => String(segment)).join(".")
  switch (issue.code) {
    case "invalid_type":
      return {
        path,
        code: issue.code,
        message: `expected ${issue.expected}, received ${issue.received}`,
      }
    case "invalid_string":
      return {
        path,
        code: issue.code,
        message: `invalid string (${issue.validation})`,
      }
    case "too_small":
      return { path, code: issue.code, message: "value is too small" }
    case "too_big":
      return { path, code: issue.code, message: "value is too large" }
    case "invalid_enum_value":
      return {
        path,
        code: issue.code,
        message: "value is not one of the allowed options",
      }
    case "unrecognized_keys":
      return { path, code: issue.code, message: "contains unknown keys" }
    default:
      return { path, code: issue.code, message: "invalid value" }
  }
}

function failureWarning(failure: ConfigLoadFailure): string {
  const location = failure.path ? ` at ${failure.path}` : ""
  const detail =
    failure.issues.length > 0
      ? failure.issues
          .map((issue) => (issue.path ? `${issue.path}: ${issue.message}` : issue.message))
          .join("; ")
      : failure.message
  return (
    `Warden configuration failure (${failure.source})${location}: ${detail}. ` +
    `Fail-closed: LLM-evaluated operations are blocked until the configuration is fixed.`
  )
}

function invalidConfigFailure(
  source: ConfigSource,
  message: string,
  issues: ConfigValidationIssue[],
  configPath?: string,
): ConfigLoadFailure {
  return {
    code: "WARDEN_CONFIG_INVALID",
    kind: "invalid",
    source,
    ...(configPath ? { path: configPath } : {}),
    message,
    issues,
    failClosed: true,
  }
}

function unreadableConfigFailure(
  source: ConfigSource,
  configPath: string,
  err: unknown,
): ConfigLoadFailure {
  const code = errnoCode(err)
  return {
    code: "WARDEN_CONFIG_UNREADABLE",
    kind: "unreadable",
    source,
    path: configPath,
    message: code
      ? `configuration source could not be read (${code})`
      : "configuration source could not be read",
    issues: [],
    failClosed: true,
  }
}

function validateConfigObject(
  parsed: unknown,
  source: ConfigSource,
  configPath: string | undefined,
  warnings: string[],
): LoadedConfigSource {
  // File and inline sources share the exact same Zod schema. This schema is
  // intentionally non-strict (unknown keys are stripped), matching the
  // documented schema semantics and the existing forward-compatibility test.
  // Known keys with invalid types/values are hard failures, so a mistyped
  // `llm.enabled`, endpoint, policy value, etc. can never silently fall back.
  const result = securityGuardConfigSchema.safeParse(parsed)
  if (!result.success) {
    const failure = invalidConfigFailure(
      source,
      "configuration validation failed",
      result.error.issues.map(describeZodIssue),
      configPath,
    )
    warnings.push(failureWarning(failure))
    return { failure }
  }
  return { config: result.data }
}

function loadConfigFile(
  configPath: string,
  source: "global" | "project",
  warnings: string[],
): LoadedConfigSource {
  let raw: string
  try {
    raw = readFileSync(configPath, "utf-8")
  } catch (err) {
    const failure = unreadableConfigFailure(source, configPath, err)
    warnings.push(failureWarning(failure))
    return { failure }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    // Never include a JSON parser message here: engine-specific messages can
    // echo a snippet of the document, which may contain API keys.
    const failure = invalidConfigFailure(
      source,
      "configuration is not valid JSON",
      [{ path: "", code: "invalid_json", message: "not valid JSON" }],
      configPath,
    )
    warnings.push(failureWarning(failure))
    return { failure }
  }

  return validateConfigObject(parsed, source, configPath, warnings)
}

function loadInlineConfig(
  inlineConfig: unknown,
  warnings: string[],
): LoadedConfigSource {
  return validateConfigObject(inlineConfig, "inline", undefined, warnings)
}

/**
 * Configuration returned when any present source is invalid/unreadable.
 *
 * It deliberately retains Warden's deterministic defaults while forcing the LLM
 * components on with an empty provider chain. Existing LLM components fail
 * closed, so a bad config cannot silently disable intended LLM enforcement or
 * fall back to a lower layer. This is defence in depth only: index-level wiring
 * MUST inspect `failure` and register deny/block hooks for every operation.
 */
function createFailClosedConfig(): SecurityGuardConfig {
  const config = structuredClone(DEFAULT_CONFIG)
  config.llm.enabled = true
  config.llm.safetyEvaluator.enabled = true
  config.llm.outputSanitizer.enabled = true
  config.llm.outputTriage.enabled = true
  config.llm.outputTextTriage.enabled = true
  config.llm.providers = []
  config.llm.safetyEvaluator.providers = []
  config.llm.outputSanitizer.providers = []
  config.llm.outputTriage.providers = []
  config.llm.outputTextTriage.providers = []
  return config
}

const LLM_ENDPOINT_KEYS = ['baseUrl', 'model', 'apiKey', 'timeout', 'temperature', 'maxTokens', 'headers', 'healthCheckPath', 'completionsPath', 'requestPolicy'] as const
const LLM_COMPONENT_KEYS = ['safetyEvaluator', 'outputTriage', 'outputTextTriage', 'outputSanitizer'] as const

/** Default generation cap — high enough to admit any legitimate evaluation
 * (~45 min of pure generation on CPU inference), finite enough to convert a
 * true runaway into a bounded failure. A command whose evaluation cannot
 * conclude within this budget is itself the risk signal (fail-closed). */
export const DEFAULT_MAX_TOKENS = 32768

/**
 * Ensure a provider object has all required fields with safe defaults.
 * Applied to every provider during config resolution so the config
 * object fulfills its LlmProviderConfig type contract.
 */
function normalizeProviderObj(raw: Record<string, unknown>, index: number): Record<string, unknown> {
  return {
    name: raw.name || `provider-${index + 1}`,
    cooldown: raw.cooldown ?? 0,
    requestPolicy: raw.requestPolicy,
    baseUrl: raw.baseUrl || "",
    model: raw.model || "",
    apiKey: raw.apiKey || "",
    timeout: raw.timeout || 0,
    temperature: raw.temperature ?? 0,
    maxTokens: raw.maxTokens ?? DEFAULT_MAX_TOKENS,
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
      if (key !== "requestPolicy") hasAny = true
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
    sharedProviders = normalizeProviders(sharedProviders.map((provider) => ({
      ...(provider as Record<string, unknown>),
      requestPolicy: (provider as Record<string, unknown>).requestPolicy ?? llm.requestPolicy,
    })))
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
        compConfig.providers = normalizeProviders(compProviders.map((provider) => ({
          ...(provider as Record<string, unknown>),
          requestPolicy: (provider as Record<string, unknown>).requestPolicy ?? compConfig.requestPolicy,
        })))
      }
    }
  }
}

/**
 * Canonicalize tool-name lists in the resolved config without touching the
 * user's config files. Legacy V1 names (`bash`, `task`) become V2 names
 * (`shell`, `subagent`); duplicates are removed and order is preserved.
 */
function normalizeConfiguredToolLists(config: SecurityGuardConfig): void {
  config.excludedTools = normalizeToolList(config.excludedTools)
  config.blockedTools = normalizeToolList(config.blockedTools)
  config.llm.safetyEvaluator.tools = normalizeToolList(config.llm.safetyEvaluator.tools)
  config.llm.outputSanitizer.tools = normalizeToolList(config.llm.outputSanitizer.tools)
}

export interface LoadConfigOptions {
  /**
   * Skip loading global config from ~/.config/opencode/opencode-warden.json
   * Useful for tests to avoid interference from user's actual global config.
   */
  skipGlobalConfig?: boolean
  /**
   * Inline plugin options, exactly as supplied by OpenCode as `ctx.options`
   * (top-level Warden config keys, e.g. the plugin entry's `options` object).
   *
   * Inline options are used ONLY when neither the global nor the project
   * `opencode-warden.json` path exists. If either path exists — even if it is
   * invalid or unreadable — inline options are ignored entirely so file-based
   * configuration always wins and is never silently shadowed.
   */
  inlineConfig?: unknown
}

export function loadConfig(
  projectDir: string,
  options?: LoadConfigOptions,
): LoadConfigResult {
  const warnings: string[] = []

  // Start with defaults
  let config: SecurityGuardConfig = structuredClone(DEFAULT_CONFIG)

  const homeDir = process.env.HOME || process.env.USERPROFILE || "~"
  const globalConfigPath = join(
    homeDir,
    ".config",
    "opencode",
    "opencode-warden.json",
  )
  const projectConfigPath = join(
    projectDir,
    ".opencode",
    "opencode-warden.json",
  )

  // Layer 1 (+2) presence check. A skipped global config is not a source at
  // all (test isolation), but the project path is always checked.
  const globalConfigExists =
    !options?.skipGlobalConfig && configPathExists(globalConfigPath)
  const projectConfigExists = configPathExists(projectConfigPath)
  const anyFileSourceExists = globalConfigExists || projectConfigExists

  const failures: ConfigLoadFailure[] = []

  if (anyFileSourceExists) {
    // ANY present file source disables inline configuration entirely.
    const globalSource = globalConfigExists
      ? loadConfigFile(globalConfigPath, "global", warnings)
      : undefined
    const projectSource = projectConfigExists
      ? loadConfigFile(projectConfigPath, "project", warnings)
      : undefined

    if (globalSource?.failure) failures.push(globalSource.failure)
    if (projectSource?.failure) failures.push(projectSource.failure)

    if (failures.length === 0) {
      if (globalSource?.config) {
        resolveLlmInheritance(globalSource.config)
        config = deepMerge(config, globalSource.config) as SecurityGuardConfig
      }
      if (projectSource?.config) {
        resolveLlmInheritance(projectSource.config)
        config = deepMerge(config, projectSource.config) as SecurityGuardConfig
      }
    } else {
      // Do NOT fall back to the valid layer, defaults, or inline options.
      config = createFailClosedConfig()
    }
  } else if (options?.inlineConfig !== undefined) {
    const inlineSource = loadInlineConfig(options.inlineConfig, warnings)
    if (inlineSource.failure) {
      failures.push(inlineSource.failure)
      config = createFailClosedConfig()
    } else if (inlineSource.config) {
      resolveLlmInheritance(inlineSource.config)
      config = deepMerge(config, inlineSource.config) as SecurityGuardConfig
    }
  }

  // In-memory compatibility layer only — never rewrite the user's files.
  normalizeConfiguredToolLists(config)

  return { config, warnings, failure: failures[0] ?? null }
}

export { DEFAULT_CONFIG } from "./defaults.js"
export { securityGuardConfigSchema } from "./schema.js"
export type { SecurityGuardUserConfig } from "./schema.js"
