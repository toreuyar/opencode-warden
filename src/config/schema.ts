import { z } from "zod"

const patternCategorySchema = z.enum([
  "api-keys",
  "credentials",
  "private-keys",
  "docker",
  "kubernetes",
  "cloud",
  "pii-email",
  "pii-phone",
  "pii-ssn",
  "pii-credit-card",
  "pii-ip-address",
])

const confidenceLevelSchema = z.enum(["low", "medium", "high"])

const riskLevelSchema = z.enum(["none", "low", "medium", "high", "critical"])

const safetyActionModeSchema = z.enum(["block", "permission", "warn"])
const outputActionModeSchema = z.enum(["redact", "warn", "pass"])

const customPatternSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  category: patternCategorySchema,
  pattern: z.string().min(1),
  redactTemplate: z.string(),
  confidence: confidenceLevelSchema,
})

const auditConfigSchema = z.object({
  enabled: z.boolean().optional(),
  filePath: z.string().optional(),
  maxFileSize: z.number().positive().optional(),
  maxFiles: z.number().int().positive().optional(),
  verbosity: z.enum(["quiet", "normal", "verbose"]).optional(),
})

const diagnosticLogSchema = z.object({
  enabled: z.boolean().optional(),
  filePath: z.string().optional(),
  maxFileSize: z.number().positive().optional(),
  maxFiles: z.number().int().positive().optional(),
})

const envSanitizerSchema = z.object({
  enabled: z.boolean().optional(),
  stripPatterns: z.array(z.string()).optional(),
})

const indirectExecutionSchema = z.object({
  enabled: z.boolean().optional(),
  scriptExtensions: z.array(z.string()).optional(),
  systemPaths: z.array(z.string()).optional(),
  maxContentSize: z.number().int().positive().optional(),
  blockBinaries: z.boolean().optional(),
  interpreters: z.array(z.string()).optional(),
  systemPrompt: z.string().optional(),
  promptTemplate: z.string().optional(),
})

const llmEndpointSchema = z.object({
  baseUrl: z.string().url().optional(),
  model: z.string().optional(),
  apiKey: z.string().optional(),
  timeout: z.number().positive().optional(),
  temperature: z.number().min(0).max(2).optional(),
  headers: z.record(z.string()).optional(),
  healthCheckPath: z.string().optional(),
  completionsPath: z.string().optional(),
})

const llmProviderSchema = llmEndpointSchema.extend({
  name: z.string().optional(),
  cooldown: z.number().min(0).optional(),
})

const llmOutputSanitizerSchema = llmEndpointSchema.extend({
  enabled: z.boolean().optional(),
  providers: z.array(llmProviderSchema).optional(),
  tools: z.array(z.string()).optional(),
  bypassedCommands: z.array(z.string()).optional(),
  skipWhenRegexClean: z.boolean().optional(),
  maxOutputSize: z.number().int().min(0).optional(),
  systemPrompt: z.string().optional(),
  promptTemplate: z.string().optional(),
  actionMode: outputActionModeSchema.optional(),
})

const operationalProfileValueSchema = z.union([
  z.boolean(),
  z.object({
    enabled: z.boolean(),
    additionalPatterns: z.array(z.string()).optional(),
  }),
])

const llmSafetyEvaluatorSchema = llmEndpointSchema.extend({
  enabled: z.boolean().optional(),
  providers: z.array(llmProviderSchema).optional(),
  tools: z.array(z.string()).optional(),
  blockThreshold: riskLevelSchema.optional(),
  warnThreshold: riskLevelSchema.optional(),
  bypassedCommands: z.array(z.string()).optional(),
  allowedOperations: z.array(z.string()).optional(),
  operationalProfiles: z.record(z.string(), operationalProfileValueSchema).optional(),
  systemPrompt: z.string().optional(),
  promptTemplate: z.string().optional(),
  actionMode: safetyActionModeSchema.optional(),
})

const llmOutputTriageSchema = llmEndpointSchema.extend({
  enabled: z.boolean().optional(),
  providers: z.array(llmProviderSchema).optional(),
  systemPrompt: z.string().optional(),
  promptTemplate: z.string().optional(),
})

const llmOutputTextTriageSchema = llmEndpointSchema.extend({
  enabled: z.boolean().optional(),
  providers: z.array(llmProviderSchema).optional(),
  systemPrompt: z.string().optional(),
  promptTemplate: z.string().optional(),
})

const llmConfigSchema = z.object({
  enabled: z.boolean().optional(),
  debug: z.boolean().optional(),
  contextAccumulation: z.boolean().optional(),
  contextDetectionsOnly: z.boolean().optional(),
  maxContextPairs: z.number().int().positive().optional(),
  maxContextChars: z.number().int().positive().optional(),
  // Shared endpoint (inherited by components when their own field is not set)
  baseUrl: z.string().url().optional(),
  model: z.string().optional(),
  apiKey: z.string().optional(),
  timeout: z.number().positive().optional(),
  temperature: z.number().min(0).max(2).optional(),
  headers: z.record(z.string()).optional(),
  healthCheckPath: z.string().optional(),
  completionsPath: z.string().optional(),
  // Shared provider chain (inherited by components that don't define their own)
  providers: z.array(llmProviderSchema).optional(),
  // Components
  safetyEvaluator: llmSafetyEvaluatorSchema.optional(),
  outputTriage: llmOutputTriageSchema.optional(),
  outputTextTriage: llmOutputTextTriageSchema.optional(),
  outputSanitizer: llmOutputSanitizerSchema.optional(),
})

export const securityGuardConfigSchema = z.object({
  categories: z.record(patternCategorySchema, z.boolean()).optional(),
  disabledPatterns: z.array(z.string()).optional(),
  customPatterns: z.array(customPatternSchema).optional(),
  whitelistedPaths: z.array(z.string()).optional(),
  blockedFilePaths: z.array(z.string()).optional(),
  excludedTools: z.array(z.string()).optional(),
  blockedTools: z.array(z.string()).optional(),
  sshOnlyMode: z.boolean().optional(),
  notifications: z.boolean().optional(),
  audit: auditConfigSchema.optional(),
  diagnosticLog: diagnosticLogSchema.optional(),
  env: envSanitizerSchema.optional(),
  indirectExecution: indirectExecutionSchema.optional(),
  llm: llmConfigSchema.optional(),
})

export type SecurityGuardUserConfig = z.infer<typeof securityGuardConfigSchema>
