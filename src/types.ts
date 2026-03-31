// ─── SSH Types ───

export type SshCommandType = "ssh" | "scp" | "sftp"

export interface ParsedSshCommand {
  type: SshCommandType
  rawCommand: string
  user?: string
  host: string
  port?: number
  innerCommand?: string
  scpSources?: string[]
  scpDestination?: string
  scpDirection?: "upload" | "download"
  options?: string[]
  identityFile?: string
}

// ─── Pattern Categories ───

export type PatternCategory =
  | "api-keys"
  | "credentials"
  | "private-keys"
  | "docker"
  | "kubernetes"
  | "cloud"
  | "pii-email"
  | "pii-phone"
  | "pii-ssn"
  | "pii-credit-card"
  | "pii-ip-address"

// ─── Detection Types ───

export type ConfidenceLevel = "low" | "medium" | "high"
export type PatternSource = "builtin" | "user" | "ai"

export interface DetectionPattern {
  id: string
  name: string
  category: PatternCategory
  pattern: RegExp
  redact: (match: string) => string
  confidence: ConfidenceLevel
  source?: PatternSource
}

export interface DetectionMatch {
  patternId: string
  patternName: string
  category: PatternCategory
  confidence: ConfidenceLevel
  original: string
  redacted: string
  startIndex: number
  endIndex: number
}

export interface ScanResult {
  redacted: string
  matches: DetectionMatch[]
  hasDetections: boolean
}

// ─── Written File Registry Types ───

export interface WrittenFileMetadata {
  timestamp: string
  tool: string
  filePath: string
  hasExecutableExtension: boolean
}

// ─── Indirect Execution Config ───

export interface IndirectExecutionConfig {
  enabled: boolean
  scriptExtensions: string[]
  systemPaths: string[]
  maxContentSize: number
  blockBinaries: boolean
  interpreters: string[]
  systemPrompt: string
  promptTemplate: string
}

// ─── Configuration Types ───

export interface EnvSanitizerConfig {
  enabled: boolean
  stripPatterns: string[]
}

export type RiskLevel = "none" | "low" | "medium" | "high" | "critical"

// ─── Action Mode Types ───

export type SafetyActionMode = "block" | "permission" | "warn"
export type OutputActionMode = "redact" | "warn" | "pass"

// ─── Operational Profiles ───

export interface OperationalProfileConfig {
  enabled: boolean
  additionalPatterns?: string[]
}

export type OperationalProfileValue = boolean | OperationalProfileConfig

// ─── LLM Endpoint Config (shared shape for each component) ───

export interface LlmEndpointConfig {
  baseUrl: string
  model: string
  apiKey: string
  timeout: number
  temperature: number
  headers: Record<string, string>
  healthCheckPath: string
  completionsPath: string
}

// ─── LLM Provider Config (endpoint + fallback chain metadata) ───

export interface LlmProviderConfig extends LlmEndpointConfig {
  name: string
  cooldown: number
}

export interface AuditConfig {
  enabled: boolean
  filePath: string
  maxFileSize: number
  maxFiles: number
  verbosity: "quiet" | "normal" | "verbose"
}

export interface DiagnosticLogConfig {
  enabled: boolean
  filePath: string
  maxFileSize: number
  maxFiles: number
}

export interface CustomPatternConfig {
  id: string
  name: string
  category: PatternCategory
  pattern: string
  redactTemplate: string
  confidence: ConfidenceLevel
}

export interface SecurityGuardConfig {
  categories: Record<PatternCategory, boolean>
  disabledPatterns: string[]
  customPatterns: CustomPatternConfig[]
  whitelistedPaths: string[]
  blockedFilePaths: string[]
  excludedTools: string[]
  blockedTools: string[]
  sshOnlyMode: boolean
  notifications: boolean
  audit: AuditConfig
  diagnosticLog: DiagnosticLogConfig
  env: EnvSanitizerConfig
  indirectExecution: IndirectExecutionConfig
  llm: {
    enabled: boolean
    debug: boolean
    contextAccumulation: boolean
    contextDetectionsOnly: boolean
    maxContextPairs: number
    maxContextChars: number
    providers: LlmProviderConfig[]
    safetyEvaluator: LlmEndpointConfig & {
      enabled: boolean
      providers: LlmProviderConfig[]
      tools: string[]
      blockThreshold: RiskLevel
      warnThreshold: RiskLevel
      bypassedCommands: string[]
      allowedOperations: string[]
      operationalProfiles: Record<string, OperationalProfileValue>
      systemPrompt: string
      promptTemplate: string
      actionMode: SafetyActionMode
    }
    outputTriage: LlmEndpointConfig & {
      enabled: boolean
      providers: LlmProviderConfig[]
      systemPrompt: string
      promptTemplate: string
    }
    outputTextTriage: LlmEndpointConfig & {
      enabled: boolean
      providers: LlmProviderConfig[]
      systemPrompt: string
      promptTemplate: string
    }
    outputSanitizer: LlmEndpointConfig & {
      enabled: boolean
      providers: LlmProviderConfig[]
      tools: string[]
      bypassedCommands: string[]
      skipWhenRegexClean: boolean
      maxOutputSize: number
      systemPrompt: string
      promptTemplate: string
      actionMode: OutputActionMode
    }
  }
}

// ─── Audit Types ───

export interface AuditEntry {
  timestamp: string
  tool: string
  hook: "before" | "after" | "env" | "compaction" | "permission"
  sessionId: string
  callId: string
  detections: Array<{
    patternId: string
    category: PatternCategory
    confidence: ConfidenceLevel
  }>
  blocked: boolean
  blockReason?: string
  redactedCount: number
  llmDetections?: number
  safetyEvaluation?: SafetyEvaluation
}

// ─── LLM Types ───

export interface LlmMessage {
  role: "system" | "user" | "assistant"
  content: string
}

export interface LlmSanitizeFinding {
  sensitive: string
  category: string
  occurrences: number
}

export interface LlmSanitizeResult {
  needsSanitization: boolean
  findings: LlmSanitizeFinding[]
}

export type RiskDimension =
  | "exfiltration"
  | "destruction"
  | "service-disruption"
  | "system-tampering"
  | "excessive-collection"
  | "privilege-escalation"
  | "persistence"
  | "resource-abuse"
  | "network-manipulation"
  | "supply-chain"
  | "indirect-execution"

export interface SafetyEvaluation {
  safe: boolean
  riskLevel: RiskLevel
  riskDimensions: RiskDimension[]
  explanation: string
  suggestedAlternative: string
  recommendation: "allow" | "warn" | "block"
}

// ─── Session Stats Types ───

export interface SessionStatsData {
  sessionId: string
  startedAt: string
  totalToolCalls: number
  totalDetections: number
  detectionsByCategory: Record<PatternCategory, number>
  blockedAttempts: number
  redactedCount: number
  blockedFilePaths: string[]
  llmDetections: number
  safetyBlocks: number
  safetyWarnings: number
  timeline: TimelineEvent[]
}

export interface TimelineEvent {
  timestamp: string
  type: "detection" | "block" | "pass" | "safety-block" | "safety-warn"
  tool: string
  details: string
  category?: PatternCategory
}

// ─── Toast Rate Limiter ───

export interface ToastState {
  lastToastTime: number
  minInterval: number
}

// ─── Plugin Client Types ───

export type LogLevel = "debug" | "info" | "warn" | "error"
export type ToastVariant = "info" | "success" | "warning" | "error"

/**
 * Minimal interface for the OpenCode SDK client methods we use.
 * Compatible with the actual SDK client — we only access these methods.
 */
export interface PluginClient {
  app: {
    log: (opts: {
      body: { service: string; level: LogLevel; message: string }
    }) => Promise<unknown>
  }
  session: {
    prompt: (opts: {
      path: { id: string }
      body: {
        noReply?: boolean
        parts: Array<{ type: string; text: string }>
      }
    }) => Promise<unknown>
  }
  tui: {
    showToast: (opts: {
      body: { message: string; variant: ToastVariant }
    }) => Promise<unknown>
  }
}
