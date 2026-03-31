# Developer Guide

This document provides an in-depth walkthrough of the OpenCode Warden codebase for contributors and maintainers. It covers the project structure, every module's internal workings, data flows, algorithms, design decisions, and patterns used throughout the code.

## Table of Contents

- [Project Setup](#project-setup)
- [Directory Structure](#directory-structure)
- [Architecture Overview](#architecture-overview)
- [Plugin Entry Point — `src/index.ts`](#plugin-entry-point--srcindexts)
- [Type System — `src/types.ts`](#type-system--srctypests)
- [Configuration System — `src/config/`](#configuration-system--srcconfig)
- [Detection Engine — `src/detection/`](#detection-engine--srcdetection)
- [Hook System — `src/hooks/`](#hook-system--srchooks)
- [LLM Integration — `src/llm/`](#llm-integration--srcllm)
- [Audit System — `src/audit/`](#audit-system--srcaudit)
- [Custom Tools — `src/tools/`](#custom-tools--srctools)
- [Utilities — `src/utils/`](#utilities--srcutils)
- [Testing — `tests/`](#testing--tests)
- [Key Algorithms](#key-algorithms)
- [Error Handling Philosophy](#error-handling-philosophy)
- [Adding New Features](#adding-new-features)
- [Code Conventions](#code-conventions)

---

## Project Setup

### Prerequisites

- **Bun** (v1.0+) — runtime and test runner
- **TypeScript** (v5.5+) — strict mode enabled

### Commands

```bash
bun install          # Install dependencies
bun test             # Run all tests
bun run typecheck    # TypeScript type checking (tsc --noEmit)
bun run build        # Bundle for distribution (bun build → dist/)
```

### TypeScript Configuration

The project uses strict TypeScript with these notable settings (`tsconfig.json`):

| Setting | Value | Purpose |
|---|---|---|
| `target` | `ESNext` | Modern JavaScript output |
| `module` | `ESNext` | ES module format |
| `moduleResolution` | `bundler` | Bun-compatible module resolution |
| `strict` | `true` | Full strict type checking |
| `noUnusedLocals` | `true` | Error on unused variables |
| `noUnusedParameters` | `true` | Error on unused function parameters |
| `isolatedModules` | `true` | Each file is an independent module |
| `declaration` | `true` | Generate `.d.ts` files |
| `types` | `["bun-types"]` | Bun runtime type definitions |

Source lives in `src/`, tests in `tests/` (excluded from compilation), output goes to `dist/`.

### Dependencies

| Package | Type | Purpose |
|---|---|---|
| `zod` | Runtime | Configuration schema validation |
| `@opencode-ai/plugin` | Peer/Dev | OpenCode plugin SDK (hook types, tool builder) |
| `@types/bun` | Dev | Bun runtime type definitions |
| `typescript` | Dev | TypeScript compiler |

---

## Directory Structure

```
src/
├── index.ts                         # Plugin entry point, hook wiring, tool registration
├── types.ts                         # All TypeScript type definitions
│
├── config/
│   ├── index.ts                     # Configuration loading and hierarchical merging
│   ├── defaults.ts                  # Hardcoded default configuration values
│   └── schema.ts                    # Zod validation schemas
│
├── detection/
│   ├── index.ts                     # Public API: createDetectionEngine()
│   ├── engine.ts                    # Core DetectionEngine class (scan, overlap resolution)
│   ├── redactor.ts                  # Redaction helper functions
│   └── patterns/
│       ├── index.ts                 # Pattern aggregation and filtering
│       ├── api-keys.ts              # 20 API key patterns
│       ├── credentials.ts           # 7 credential/connection string patterns
│       ├── private-keys.ts          # 7 private key patterns (PEM blocks)
│       ├── docker.ts                # 4 Docker secret patterns
│       ├── kubernetes.ts            # 6 Kubernetes secret patterns
│       ├── cloud.ts                 # 16 cloud provider patterns
│       └── pii.ts                   # 7 PII patterns (with Luhn and IP validation)
│
├── hooks/
│   ├── input-sanitizer.ts           # tool.execute.before — input scanning and safety eval
│   ├── output-redactor.ts           # tool.execute.after — output redaction
│   ├── env-sanitizer.ts             # shell.env — environment variable sanitization
│   ├── permission-handler.ts        # permission.ask — OpenCode permission integration
│   ├── compaction-context.ts        # experimental.session.compacting — policy injection
│   └── security-policy.ts           # Builds security policy text for LLM context
│
├── llm/
│   ├── index.ts                     # LlmSanitizer class + module re-exports
│   ├── client.ts                    # HTTP client for LLM API (fetch-based)
│   ├── context.ts                   # ConversationContext — sliding window history
│   ├── prompts.ts                   # System prompts, prompt templates, renderTemplate()
│   └── safety-evaluator.ts          # SafetyEvaluator class (10-dimension risk assessment)
│
├── audit/
│   ├── index.ts                     # AuditLogger orchestrator
│   ├── file-logger.ts               # File-based logging with buffering and rotation
│   └── session-stats.ts             # In-memory session statistics and timeline
│
├── tools/
│   ├── security-dashboard.ts        # security_dashboard tool implementation
│   ├── security-report.ts           # security_report tool implementation
│   └── rules-manage.ts             # security_rules tool implementation
│
└── utils/
    ├── paths.ts                     # Glob matching, file path extraction from tool args
    └── deep-scan.ts                 # Recursive object/array scanning for secrets

tests/
├── config.test.ts                   # Configuration defaults and Zod schema validation
├── hooks.test.ts                    # Hook behavior tests (input, output, env, compaction)
└── detection-patterns.test.ts       # Pattern detection tests across all categories
```

---

## Architecture Overview

Security Guard is structured as a layered interception system. Here is how the components relate:

```
┌──────────────────────────────────────────────────────────────────────┐
│                        OpenCode Runtime                             │
│                                                                     │
│  User prompt → AI agent → Tool call → [Plugin Hooks] → Tool exec   │
└──────────────┬───────────────────────────────────┬──────────────────┘
               │                                   │
               ▼                                   ▼
┌──────────────────────────┐    ┌──────────────────────────────────┐
│     src/index.ts         │    │    Hook Pipeline (5 hooks)       │
│  Plugin entry point      │    │                                  │
│  - Config loading        │───▶│  permission.ask → input-sanitizer│
│  - Component init        │    │  shell.env → output-redactor     │
│  - Hook registration     │    │  session.compacting              │
│  - Tool registration     │    └───────────┬──────────────────────┘
│  - Session lifecycle     │                │
└──────────────────────────┘                │
                                            ▼
        ┌───────────────────────────────────────────────────┐
        │              Shared Dependencies                   │
        │                                                    │
        │  DetectionEngine ◄─── Pattern Registry             │
        │  SafetyEvaluator ◄─── LLM Client + Prompts        │
        │  LlmSanitizer   ◄─── LLM Client + Context         │
        │  AuditLogger     ◄─── FileLogger                   │
        │  SessionStats    ◄─── Timeline tracking             │
        │  ToastState      ◄─── Rate limiter                  │
        │  evaluatedCalls  ◄─── Set<string> (deduplication)   │
        │  sessionAllowlist◄─── Set<string> (file overrides)  │
        └───────────────────────────────────────────────────┘
```

### Data Flow Summary

1. **Configuration** loads from defaults → global file → project file (deep merge)
2. **Detection engine** is built from enabled categories + disabled patterns + custom patterns
3. **LLM components** are conditionally initialized if `llm.enabled` is true
4. **Hooks** are created as closures that close over shared state
5. **Each tool call** flows through: `permission.ask` (optional) → `shell.env` (if shell) → `tool.execute.before` → tool executes → `tool.execute.after`
6. **Session events** reset all mutable state

---

## Plugin Entry Point — `src/index.ts`

**Lines**: ~298 | **Exports**: `SecurityGuard` (Plugin function), default export

This is the main file that OpenCode loads. It exports an async function conforming to the `Plugin` type from `@opencode-ai/plugin`.

### Initialization Sequence

```typescript
export const SecurityGuard: Plugin = async ({ client: sdkClient, directory }) => {
```

The plugin receives the OpenCode SDK client and the project directory. It then:

1. **Casts the SDK client** to our `PluginClient` interface (we only use `app.log`, `session.prompt`, `tui.showToast`)

2. **Loads configuration** via `loadConfig(directory)` — merges defaults → global → project configs

3. **Creates the detection engine** via `createDetectionEngine(config)` — compiles all regex patterns

4. **Resolves the audit log path** — converts relative paths to absolute using `directory`

5. **Creates the audit logger** with the resolved config

6. **Creates session stats** tracker

7. **Initializes LLM components** (if `config.llm.enabled`):
   - Creates `LlmSanitizer` instance
   - Creates `SafetyEvaluator` instance
   - Runs a non-blocking health check (doesn't delay plugin startup)
   - Shows a toast if the LLM is unreachable

 8. **Creates shared state objects**:
    - `toastState: ToastState` — rate limiter (2000ms interval)
    - `sessionAllowlist: Set<string>` — temporary file access overrides (config-based whitelistedPaths)
    - `evaluatedCalls: Set<string>` — deduplication between `permission.ask` and `tool.execute.before`
    - `policyInjected: boolean` — tracks if security policy was injected into session

 9. **Creates all hook handlers** by calling factory functions with dependencies

 10. **Creates custom tool definitions** for the 3 built-in tools

11. **Logs startup information** (pattern count, active categories, LLM status)

### Returned Hook Object

The plugin returns an object with these hooks:

```typescript
return {
  "tool.execute.before": async (input, output) => {
    // Inject security policy on first tool call (one-time)
    if (!policyInjected && input.sessionID) {
      policyInjected = true
      await client.session.prompt({ ... }) // Inject policy text
    }
    return inputSanitizer(input, output)
  },
  "tool.execute.after": outputRedactor,
  "permission.ask": permissionHandler,
  "shell.env": envSanitizer,
  "experimental.session.compacting": compactionContext,

  event: async ({ event }) => {
    if (event.type === "session.created") {
      // Reset all mutable state
      sessionStats.reset("")
      sessionAllowlist.clear()
      evaluatedCalls.clear()
      policyInjected = false
      llmSanitizer?.reset()
      safetyEvaluator?.reset()
    }
  },

  tool: {
    security_dashboard: tool({ ... }),
    security_report: tool({ ... }),
    security_rules: tool({ ... }),
  },
}
```

### Design Decisions

- **Security policy injection**: Done on the first tool call (not session creation) because we need a `sessionID` to call `session.prompt`. This ensures the AI knows about security constraints from the start.
- **Non-blocking health check**: The LLM health check runs in the background to avoid delaying plugin startup. If it fails, we show a toast and fall back to regex-only mode.
- **Shared mutable state**: `evaluatedCalls`, `sessionAllowlist`, and `toastState` are shared by reference across hook closures. This is safe because all hooks run sequentially within the OpenCode event loop (no concurrent access).

---

## Type System — `src/types.ts`

**Lines**: ~265 | **Purpose**: Central type definitions for the entire application

All types are defined in one file for simplicity and import convenience. The key type hierarchies:

### Pattern System Types

```
PatternCategory (11 categories)
    │
    ├── DetectionPattern (compiled regex + redaction function)
    │       ├── id: string
    │       ├── name: string
    │       ├── category: PatternCategory
    │       ├── pattern: RegExp        ← compiled regex
    │       ├── redact: (match) => string  ← redaction function
    │       └── confidence: ConfidenceLevel
    │
    ├── DetectionMatch (single occurrence found)
    │       ├── patternId, patternName, category, confidence
    │       ├── original: string       ← what was found
    │       ├── redacted: string       ← what it was replaced with
    │       └── startIndex, endIndex   ← position in input
    │
    └── ScanResult (output of engine.scan())
            ├── redacted: string       ← full text with replacements
            ├── matches: DetectionMatch[]
            └── hasDetections: boolean
```

### Configuration Types

The `SecurityGuardConfig` interface is the master configuration type. It's a flat interface with nested objects for `audit`, `env`, and `llm` sections. The `llm` section further nests `outputSanitizer` and `safetyEvaluator` configs. These nested types are defined inline rather than as separate interfaces because they're only used within `SecurityGuardConfig`.

### Action Mode Types

```typescript
SafetyActionMode = "block" | "permission" | "warn"
OutputActionMode = "redact" | "warn" | "pass"
```

These control how the plugin responds to detected threats. They were added to both the inline config types and the Zod schema.

### Risk Assessment Types

```typescript
RiskLevel = "none" | "low" | "medium" | "high" | "critical"
RiskDimension = "exfiltration" | "destruction" | ... (10 dimensions)

SafetyEvaluation = {
  safe: boolean
  riskLevel: RiskLevel
  riskDimensions: RiskDimension[]
  explanation: string
  recommendation: "allow" | "warn" | "block"
}
```

### Plugin Client Interface

```typescript
interface PluginClient {
  app: { log: (opts) => Promise<unknown> }
  session: { prompt: (opts) => Promise<unknown> }
  tui: { showToast: (opts) => Promise<unknown> }
}
```

This is a minimal interface that matches the real SDK client. We cast the SDK client to this type to avoid coupling to the full SDK type surface.

---

## Configuration System — `src/config/`

### `config/schema.ts` — Zod Validation

All user-provided configuration is validated at load time using Zod schemas. Every field is `optional()` because user configs are partial — they only specify overrides.

**Schema hierarchy:**

```
securityGuardConfigSchema
├── categories: Record<patternCategorySchema, boolean>
├── customPatterns: array(customPatternSchema)
├── audit: auditConfigSchema
├── env: envSanitizerSchema
└── llm: llmConfigSchema
      ├── outputSanitizer: llmOutputSanitizerSchema
      │     └── actionMode: outputActionModeSchema  ← z.enum(["redact", "warn", "pass"])
      └── safetyEvaluator: llmSafetyEvaluatorSchema
            └── actionMode: safetyActionModeSchema  ← z.enum(["block", "permission", "warn"])
```

**Validation rules of note:**
- `baseUrl` uses `z.string().url()` — requires valid URL format
- `temperature` uses `z.number().min(0).max(2)` — LLM temperature range
- `maxTokens` uses `z.number().int().positive()` — must be positive integer
- Pattern categories use `z.enum([...])` — rejects unknown categories

The inferred type `SecurityGuardUserConfig` is what the schema produces. It has all fields as optional, unlike `SecurityGuardConfig` which has all fields as required (filled by defaults).

### `config/defaults.ts` — Default Values

Contains `DEFAULT_CONFIG: SecurityGuardConfig` with every field filled in. Key defaults:

- All categories enabled except `pii-ip-address` (disabled due to false positives)
- 24 blocked file patterns (`.env`, `*.pem`, `*.key`, kubeconfig, tfstate, etc.)
- 24 env strip patterns (`*_SECRET`, `*_TOKEN`, `AWS_SECRET_ACCESS_KEY`, etc.)
- LLM disabled by default, debug logging enabled
- Safety evaluator: `actionMode: "block"`, `blockThreshold: "high"`, `warnThreshold: "medium"`
- Output sanitizer: `actionMode: "redact"`
- Audit: enabled, 10MB max file, 5 rotated files, `"normal"` verbosity

### `config/index.ts` — Loading and Merging

The `loadConfig()` function implements a three-layer configuration hierarchy:

```typescript
function loadConfig(projectDir: string): SecurityGuardConfig {
  let config = structuredClone(DEFAULT_CONFIG)  // Layer 0: defaults

  // Layer 1: Global config
  const globalConfig = loadConfigFile("~/.config/opencode/opencode-warden.json")
  if (globalConfig) config = deepMerge(config, globalConfig)

  // Layer 2: Project config
  const projectConfig = loadConfigFile(".opencode/opencode-warden.json")
  if (projectConfig) config = deepMerge(config, projectConfig)

  return config
}
```

**`deepMerge(target, source)`** is a recursive merge function:
- Objects are merged recursively (key by key)
- Arrays are replaced entirely (not concatenated)
- `undefined` values in source are skipped
- `null` values in source overwrite target
- Primitives in source overwrite target

This means if a user specifies `blockedFilePaths: [".env"]`, it completely replaces the default list rather than appending to it. This is intentional — users can fully control which paths are blocked.

**`loadConfigFile(path)`** reads a JSON file, validates it with Zod, and returns the validated config or `undefined` on error. Validation errors are logged to console but don't crash the plugin.

---

## Detection Engine — `src/detection/`

### `detection/engine.ts` — DetectionEngine Class

The `DetectionEngine` is the core scanning component. It holds an array of `DetectionPattern` objects and provides two main methods.

#### `scan(input: string): ScanResult`

This is the most important method in the codebase. Here is its algorithm:

```
1. Early return if input is empty

2. For each pattern in this.patterns:
   a. Create a fresh RegExp from pattern.source/flags (reset lastIndex)
   b. Execute regex globally (while loop with exec)
   c. For each match:
      - Call pattern.redact(match[0]) to get replacement
      - Skip if redacted === original (pattern chose not to redact)
      - Create DetectionMatch with position, original, redacted
   d. Collect all matches

3. If no matches found, return early with unchanged input

4. Resolve overlapping matches (see resolveOverlaps below)

5. Sort resolved matches by startIndex DESCENDING (end → start)

6. Apply replacements using substring concatenation:
   redacted = redacted.substring(0, m.startIndex)
            + m.redacted
            + redacted.substring(m.endIndex)

   (Working from end to start preserves earlier indices)

7. Re-sort matches by startIndex ASCENDING (for output)

8. Return { redacted, matches: resolved, hasDetections: true }
```

**Why create a fresh RegExp?** Global regexes (`/g` flag) maintain `lastIndex` state. If the same pattern object is reused across calls, `lastIndex` would carry over and skip matches. Creating a fresh `RegExp` from `pattern.source` and `pattern.flags` resets this state.

**Why apply replacements from end to start?** When you replace text at position N, all positions after N shift. By working backwards, earlier positions remain valid.

#### `resolveOverlaps(matches: DetectionMatch[]): DetectionMatch[]`

When multiple patterns match overlapping regions, we keep the "best" match:

```
1. Sort by: startIndex ASC → length DESC → confidence DESC

2. Initialize result with first match

3. For each subsequent match:
   a. If it overlaps with the last result entry (startIndex < last.endIndex):
      - Keep whichever is longer
      - If same length, keep higher confidence
   b. If no overlap: append to result

4. Return result
```

**Confidence ordering**: `high=3`, `medium=2`, `low=1`

**Example**: If both "OpenAI API Key" (high confidence, 40 chars) and "Bearer Token" (medium confidence, 30 chars) match overlapping regions, the longer OpenAI pattern wins. If they're the same length, the higher confidence wins.

#### `hasSensitiveData(input: string): boolean`

Short-circuit version of `scan()` — returns `true` on the first match that would actually be redacted (where `redact(match) !== match`). Used for quick boolean checks without building the full result.

#### `setPatterns(patterns: DetectionPattern[]): void`

Replaces the pattern array at runtime. Used by the `security_rules` tool when custom patterns are added or removed. The engine immediately uses the new patterns for subsequent scans.

### `detection/patterns/index.ts` — Pattern Aggregation

The `getPatterns()` function assembles the final pattern list:

```typescript
function getPatterns(enabledCategories, disabledPatterns, customPatterns) {
  const disabledSet = new Set(disabledPatterns)

  // 1. Filter built-in patterns
  const patterns = ALL_BUILTIN_PATTERNS.filter(
    p => enabledCategories[p.category] && !disabledSet.has(p.id)
  )

  // 2. Add custom patterns (compile regex, skip invalid)
  for (const custom of customPatterns) {
    if (!enabledCategories[custom.category]) continue
    if (disabledSet.has(custom.id)) continue
    try {
      patterns.push({
        ...custom,
        pattern: new RegExp(custom.pattern, "g"),
        redact: () => custom.redactTemplate,  // Static replacement
      })
    } catch { /* log and skip invalid regex */ }
  }

  return patterns
}
```

Custom patterns use a static `redact` function that always returns the `redactTemplate` string. Built-in patterns use dynamic redaction functions that may inspect the match (e.g., PII patterns that validate before redacting).

### `detection/patterns/*.ts` — Pattern Definitions

Each pattern file exports an array of `DetectionPattern` objects. Patterns follow this structure:

```typescript
{
  id: "openai-api-key",
  name: "OpenAI API Key",
  category: "api-keys",
  pattern: /sk-proj-[A-Za-z0-9_-]{20,}/g,
  redact: () => "[REDACTED]",
  confidence: "high",
}
```

**Notable pattern techniques:**

- **Lookbehinds**: Several patterns use `(?<=...)` to match values only when preceded by a keyword. For example, the AWS Secret Key pattern requires the value to be preceded by an assignment operator (`=`, `:`, `"`, etc.).

- **Smart redaction**: PII patterns (credit card, IPv4) have conditional redaction functions:
  - **Credit card** (`pii.ts`): Runs Luhn checksum validation. Only redacts if the number passes Luhn. This dramatically reduces false positives from random 16-digit numbers.
  - **IPv4** (`pii.ts`): Excludes common non-sensitive IPs: `127.0.0.1`, `0.0.0.0`, `192.168.*`, `10.*`, `255.255.255.*`. Only redacts likely-public IPs.

- **Multi-line patterns**: Private key patterns use `[\s\S]*?` to match across line breaks within PEM blocks.

### `detection/redactor.ts` — Redaction Helpers

Contains two simple functions that both return `"[REDACTED]"`. The `maskWithEnds` function accepts parameters for backward compatibility but ignores them. All redaction now uses the uniform `[REDACTED]` marker.

---

## Hook System — `src/hooks/`

Each hook is implemented as a factory function that accepts a `deps` object and returns the actual hook handler (a closure). This pattern enables dependency injection and testability.

### `hooks/input-sanitizer.ts` — `tool.execute.before`

**Purpose**: Inspect and sanitize tool inputs before execution. Can block calls by throwing.

**Dependencies:**

```typescript
interface InputSanitizerDeps {
  engine: DetectionEngine
  config: SecurityGuardConfig
  auditLogger: AuditLogger
  sessionStats: SessionStats
  client: PluginClient
  safetyEvaluator: SafetyEvaluator | null
  toastState: ToastState
  sessionAllowlist: Set<string>
  evaluatedCalls: Set<string>
}
```

**Processing pipeline (5 steps):**

**Step 1: Record tool call** — Increments the session-level tool call counter. This always runs, even for excluded tools (but we skip it for excluded tools — the counter is incremented before the exclusion check, which is intentional to track total tool activity).

**Step 2: Check file path blocking** — Extracts a file path from the tool args (via `extractFilePath()`), checks the session allowlist first (takes priority), then checks the blocked patterns. If blocked: audit log, toast, `throw Error`. The AI sees the error message and can inform the user.

**Step 3: Regex deep scan** — Calls `deepScan(output.args, engine)` to recursively scan all string values in the args object. Detections are replaced in-place (mutating `output.args`). Category counts are recorded in session stats.

**Step 4: LLM safety evaluation** — Only runs if:
- `safetyEvaluator` is not null (LLM enabled)
- `safetyEvaluator.shouldEvaluate(tool)` returns true (tool is in the eval list)
- `safetyEvaluator.isBypassed(tool, args)` returns false (command not bypassed)
- `evaluatedCalls` does NOT contain this `callID` (not already evaluated by `permission.ask`)

**Action mode logic:**
- `"block"` mode: `recommendation === "block"` → `throw Error`; `recommendation === "warn"` → show toast
- `"permission"` mode: If already evaluated by `permission.ask` → skip. Otherwise falls back to `"block"` behavior (the permission hook didn't fire, so the tool is auto-allowed by OpenCode, but we still need to protect)
- `"warn"` mode: `recommendation === "block"` → show toast (but don't throw); `recommendation === "warn"` → show toast

**Step 5: Audit log** — Records the scan results, safety evaluation, and detection counts.

**Toast rate limiting**: The `canToast()` helper function tracks the last toast time and enforces a minimum interval (2000ms by default). This prevents toast spam when many tool calls fire in quick succession.

### `hooks/output-redactor.ts` — `tool.execute.after`

**Purpose**: Redact secrets from tool output before the AI sees them.

**Processing pipeline:**

**Pass 1: Regex scan** — Scans both `output.output` and `output.title` through the detection engine. In `"pass"` mode, detections are counted but not redacted. In `"redact"` and `"warn"` modes, text is replaced.

**Pass 2: LLM sanitization** — Second pass using the LLM for context-aware detection. Skipped in `"pass"` mode, when LLM is unavailable, or when `skipWhenRegexClean` is true and regex found nothing. The LLM receives tool context (name, args, title) to reason about whether values look like secrets.

**Toast behavior by action mode:**
- `"redact"`: Rate-limited toast showing count and method (regex vs LLM)
- `"warn"`: Always shows detailed toast (bypasses rate limiter) with categories found
- `"pass"`: Rate-limited toast saying "NOT redacted — pass mode"

### `hooks/env-sanitizer.ts` — `shell.env`

**Purpose**: Sanitize environment variables before shell commands see them.

**Two-strategy approach:**

1. **Value scanning**: Runs every env var's value through the detection engine. Secrets in values are redacted in-place.

2. **Name stripping**: Matches env var names against `stripPatterns` using glob patterns. Matching vars are replaced with `"[REDACTED]"` regardless of their value. This catches vars like `MY_SECRET=anything` where the value might not match any regex pattern but the name indicates it's sensitive.

**`matchEnvPattern()` helper**: Converts glob patterns to regex. Special characters are escaped, `*` becomes `.*`. The pattern is anchored with `^...$` for exact name matching.

### `hooks/permission-handler.ts` — `permission.ask`

**Purpose**: Integrate with OpenCode's permission system to give users informed choices.

**When does `permission.ask` fire?** Only when OpenCode's built-in permission system would normally prompt the user about a tool call. Tools that are auto-allowed in OpenCode config do NOT trigger this hook.

**Processing:**

1. **Mode gate**: Only runs if `safetyActionMode === "permission"`. Otherwise returns immediately.

2. **Tool filtering**: Checks if the tool is in the safety evaluator's tool list and not bypassed.

3. **LLM evaluation**: Calls `safetyEvaluator.evaluate()` with the tool name and metadata as args.

4. **Status mapping**:
   - `recommendation === "block"` → `output.status = "deny"` (auto-denies, no user prompt)
   - `recommendation === "warn"` → `output.status = "ask"` (shows permission prompt + risk toast)
   - `recommendation === "allow"` → no status change (OpenCode's default behavior)

5. **Deduplication**: Adds `callID` to `evaluatedCalls` set. When `tool.execute.before` fires next for this same call, it checks `evaluatedCalls` and skips re-evaluation.

**Why fall back to "block" in the input sanitizer?** When `actionMode === "permission"` but `permission.ask` didn't fire (because the tool is auto-allowed in OpenCode), the input sanitizer falls back to `"block"` behavior. This ensures that auto-allowed tools still get safety evaluation — we can't rely on the permission system for these.

### `hooks/compaction-context.ts` — `experimental.session.compacting`

**Purpose**: Inject security policy context when the session is compacted.

This is a trivial hook — it just pushes the security policy text (generated by `buildSecurityPolicyContext()`) into the compaction context array. OpenCode appends these strings to the compaction prompt, ensuring the AI retains awareness of security constraints across context window compressions.

### `hooks/security-policy.ts` — Policy Text Builder

**Purpose**: Build a markdown document that explains the security system to the AI.

The `buildSecurityPolicyContext()` function generates a structured markdown document with sections for:
- Content redaction (explains `[REDACTED]` markers)
- Blocked file paths (lists all patterns)
- Monitored categories (lists enabled categories)
- Tool call monitoring (warns about blocked commands)
- Available security tools (lists the 4 tools)

This text is injected into the AI's context in two ways:
1. On first tool call via `session.prompt()` (immediate)
2. During session compaction via the compaction hook (ongoing)

---

## LLM Integration — `src/llm/`

### `llm/client.ts` — HTTP Client

Low-level HTTP client for OpenAI-compatible chat completions APIs.

**`buildLlmHeaders(apiKey, customHeaders)`**: Merges headers in order:
1. `Content-Type: application/json` (always)
2. `Authorization: Bearer {apiKey}` (if apiKey is non-empty)
3. Custom headers (override any of the above)

This allows Azure OpenAI users to set `headers: { "api-key": "..." }` which overrides the default Bearer token.

**`callLlm(options)`**: Makes a POST request to the chat completions endpoint.

```
POST {baseUrl}{completionsPath}
Body: { model, messages, temperature, max_tokens }
Response: Extract choices[0].message.content
```

Uses `AbortController` with a configurable timeout. Debug logging includes full request and response bodies (useful for debugging prompt issues).

**`checkLlmHealth(options)`**: Makes a GET request to the health check endpoint (default: `/models`). Returns `true` if the response status is OK (2xx). Used for the non-blocking startup health check.

### `llm/context.ts` — Conversation Context

The `ConversationContext` class manages a sliding window of message history for LLM calls.

**Message structure:**

```
[system prompt] → [user₁, assistant₁] → [user₂, assistant₂] → ... → [current user]
                   └──── history pairs ────┘                        └── pending ──┘
```

**Accumulation modes:**
- `accumulate: false` (default): Stateless — only system prompt + current user message
- `accumulate: true`: Keeps history of user+assistant pairs

**Detection filtering** (`detectionsOnly: true`, default):
- Only keeps pairs where the assistant response indicated detections
- Saves context budget for meaningful exchanges

**Sliding window enforcement** (`trim()` method):
1. Drop oldest pairs if count exceeds `maxPairs` (default: 5)
2. Drop oldest pairs if total character count exceeds `maxChars` (default: 16000)

**`getMessages()`** builds the final message array: `[system, ...history, pending]`. This is what gets sent to the LLM API.

### `llm/prompts.ts` — System Prompts and Templates

Contains two large system prompts and their corresponding templates.

**`DEFAULT_SANITIZER_SYSTEM_PROMPT`** (~53 lines):
- Instructs the LLM to identify and redact sensitive data in tool outputs
- Lists 14 categories of explicitly sensitive data
- Describes contextual indicators (base64, hex strings, sensitive paths)
- Lists what NOT to redact (code, UUIDs, version strings, public keys)
- Specifies JSON response format: `{ sanitized, detections[] }`
- Principle: "When in doubt, redact"

**`DEFAULT_SAFETY_SYSTEM_PROMPT`** (~60 lines):
- Instructs the LLM to evaluate tool calls as a "senior DevOps/SRE security evaluator"
- Details all 10 risk dimensions with extensive examples for each
- Defines risk levels (none → critical)
- Describes normal vs suspicious operations
- Includes a **test scenario**: operations on `helloworld.sh` must always be flagged as `critical`
- Specifies JSON response format: `{ safe, riskLevel, riskDimensions[], explanation, recommendation }`

**`renderTemplate(template, vars)`**: Simple `{{key}}` → value replacement using `String.replaceAll()`.

**`buildSanitizePrompt()` / `buildSafetyPrompt()`**: Build the user prompt by rendering the template with tool name, args/output, and optional context. Falls back to default templates if custom template is empty.

### `llm/safety-evaluator.ts` — SafetyEvaluator Class

The `SafetyEvaluator` analyzes tool calls for safety risks.

**`isBypassed(tool, args)`**: Only applies to `bash` tool. Checks if `args.command` starts with any prefix in `bypassedCommands` (e.g., `"git status"`, `"ls"`, `"pwd"`). Safe commands skip LLM evaluation entirely.

**`shouldEvaluate(tool)`**: Returns true if the evaluator is enabled AND the tool is in the `tools` list (default: `["bash", "write", "edit", "webfetch"]`).

**`evaluate(tool, args)`**: The main evaluation method:

```
1. Build prompt from tool name and args
2. Add user message to conversation context
3. Call LLM via callLlm()
4. Parse JSON response from LLM output
5. Apply threshold logic to determine recommendation
6. Add assistant message to context (for history)
7. Return SafetyEvaluation
```

**Threshold application** (`applyThresholds()`):

```typescript
const RISK_LEVEL_ORDER = { none: 0, low: 1, medium: 2, high: 3, critical: 4 }

if (riskOrder >= blockOrder) → recommendation = "block"
if (riskOrder >= warnOrder)  → recommendation = "warn"
else                         → recommendation = "allow"
```

This overrides whatever recommendation the LLM gave. The LLM might say "allow" for a medium-risk operation, but if `warnThreshold` is `"medium"`, we override to "warn".

**Response parsing** (`parseResponse()`): Extracts JSON from the LLM response using a regex `/\{[\s\S]*\}/`. This handles cases where the LLM wraps JSON in markdown code blocks. Falls back to `{ safe: true, riskLevel: "none", recommendation: "allow" }` if parsing fails.

**Fail-open design**: If the LLM call fails (timeout, network error, parse error), the evaluator returns a safe "allow" result. This prevents the LLM being unavailable from blocking all tool calls.

### `llm/index.ts` — LlmSanitizer Class

The `LlmSanitizer` handles the second-pass output sanitization.

**`healthCheck()`**: Calls `checkLlmHealth()` and sets the `connected` flag. Uses a 5-second timeout (shorter than the normal request timeout).

**`shouldSanitize(tool)`**: Returns true if LLM is enabled, output sanitizer is enabled, and the tool is in the sanitizer's tool list.

**`sanitize(toolName, rawOutput, context?)`**: Similar flow to safety evaluation:
1. Build prompt with context (tool name, args, title)
2. Call LLM
3. Parse JSON response: `{ sanitized, detections[] }`
4. Return sanitized output with detection list

**Fail-open**: Returns the original output unchanged if the LLM call fails.

---

## Audit System — `src/audit/`

### `audit/index.ts` — AuditLogger

The `AuditLogger` orchestrates logging to both file and the OpenCode log panel.

**Verbosity filtering:**

| Verbosity | Blocked | Detections | Clean passes |
|---|---|---|---|
| `quiet` | Logged | Logged | Skipped |
| `normal` | Logged | Logged | Skipped |
| `verbose` | Logged | Logged | Logged |

**Log levels** sent to OpenCode:
- Blocked entries → `"warn"` level
- Detection entries → `"info"` level
- Clean passes → `"debug"` level (only in verbose mode)

**`formatLogMessage()`**: Creates human-readable messages for the OpenCode log panel:
- `BLOCKED: bash - Safety evaluation: Command attempts to delete system files`
- `REDACTED: 3 secret(s) in read [api-keys, credentials]`
- `PASS: bash`

### `audit/file-logger.ts` — FileLogger

Implements buffered, rotating file logging.

**Buffering strategy:**
- Entries are accumulated in an in-memory `buffer: string[]`
- Auto-flush triggers:
  - When buffer reaches 10 entries (`flushThreshold`)
  - After 1 second of inactivity (`flushInterval`)
- Manual flush via `flush()` method

**`flush()` method:**
1. Clear the flush timer
2. Join buffer entries with newlines + trailing newline
3. Check if log rotation is needed
4. Append to file using `appendFileSync`
5. Clear buffer

**Log rotation** (`rotateIfNeeded()`):
```
audit.log      → audit.log.1   (rename)
audit.log.1    → audit.log.2   (rename)
audit.log.2    → audit.log.3   (rename)
...
audit.log.N    → (dropped if > maxFiles)
```

Rotation triggers when the current file size meets or exceeds `maxFileSize` (default: 10MB). The rotation renames files from highest to lowest to avoid overwrites, then renames the current file to `.1`.

**Constructor**: Creates the log directory if it doesn't exist (`mkdirSync` with `recursive: true`).

### `audit/session-stats.ts` — SessionStats

In-memory statistics tracker for the current session.

**Tracked metrics:**
- `totalToolCalls` — every tool call regardless of detection
- `totalDetections` — regex + LLM combined
- `detectionsByCategory` — per-category counts (11 categories)
- `blockedAttempts` — file blocks + safety blocks
- `redactedCount` — total secrets redacted
- `llmDetections` — detections from LLM pass only
- `safetyBlocks` — tool calls blocked by safety evaluator
- `safetyWarnings` — tool calls warned by safety evaluator
- `blockedFilePaths` — unique list of blocked paths
- `timeline` — event log (capped at 1000, trimmed to 500)

**Timeline management**: Events are pushed to the timeline array. When it exceeds 1000 entries, the oldest 500 are dropped (keeping the most recent 500). This prevents unbounded memory growth in long sessions.

**`getReport(format)`**: Builds a formatted text report. The `"detailed"` format includes the full timeline with event type icons (BLOCK, DETECT, SAFETY-BLOCK, SAFETY-WARN, PASS).

---

## Custom Tools — `src/tools/`

### `tools/security-dashboard.ts`

Returns a formatted text dashboard showing:
1. Status section (categories, LLM connectivity, notifications)
2. Session statistics (all counters)
3. Category breakdown (non-zero categories, sorted by count)
4. Blocked file access (list of blocked paths)
5. Recent events (last 10 timeline entries)

### `tools/security-report.ts`

Thin wrapper around `SessionStats.getReport()`. Accepts an optional `format` parameter (`"summary"` or `"detailed"`).

### `tools/rules-manage.ts`

The most complex tool. Manages custom detection patterns with persistence.

**Key operations:**

**`add` action:**
1. Validate regex compiles
2. Generate ID from name (lowercase, replace non-alphanumeric with hyphens)
3. Check for duplicate IDs
4. Add to in-memory `config.customPatterns`
5. Read project config file, add pattern, write back
6. Call `reloadEngine()` to rebuild pattern list

**`remove` action:**
1. Reject if the ID belongs to a built-in pattern
2. Find and remove from in-memory config
3. Read project config file, filter out pattern, write back
4. Call `reloadEngine()`

**`reloadEngine()` helper:** Calls `getPatterns()` with the current config and passes the result to `engine.setPatterns()`. This makes the new patterns take effect immediately.

**Config file handling:** Reads/writes `.opencode/opencode-warden.json` directly. Creates the `.opencode/` directory if needed. Writes JSON with 2-space indentation + trailing newline.

---

## Utilities — `src/utils/`

### `utils/deep-scan.ts`

Recursively walks an object/array structure, scanning all string values through the detection engine.

```typescript
function deepScan(value, engine, depth = 0): DeepScanResult
```

**Type handling:**
- **string**: Scan through engine, return redacted value
- **array**: Recursively scan each element, merge match counts
- **object**: Recursively scan each value (keys are not scanned), merge match counts
- **primitives** (number, boolean, null, undefined): Pass through unchanged

**Depth limit**: 10 levels maximum. Beyond that, values pass through unscanned. This prevents infinite recursion on circular references (though those shouldn't appear in tool args).

**Returns**: A `DeepScanResult` with the redacted deep copy, total match count, and flattened array of all matches from all nested levels.

### `utils/paths.ts`

**`isBlockedPath(filePath, blockedPatterns, whitelistedPatterns)`**:
1. Normalize path (backslashes to forward slashes)
2. Check whitelist first — if any whitelist pattern matches, return `false` (not blocked)
3. Check blocklist — if any pattern matches, return `true` (blocked)
4. Return `false` (not blocked by default)

**Whitelist takes priority over blocklist.** This allows patterns like:
- Block `**/.env*`
- Whitelist `**/.env.example`

**`matchGlob(path, pattern)`**: Converts glob patterns to regex:

| Glob | Regex | Meaning |
|---|---|---|
| `*` | `[^/]*` | Match anything except directory separator |
| `**` | `.*` | Match anything including directory separators |
| `**/` | `(?:.*/)?` | Match any number of directory levels |
| `?` | `[^/]` | Match single character except separator |
| `.` | `\\.` | Literal dot |
| Special chars | `\\char` | Escaped: `(){}+^$\|[]` |

The generated regex is tested in two ways:
1. `(?:^|/)pattern$` — matches the pattern at any depth
2. `^pattern$` — matches the full path exactly

**`extractFilePath(tool, args)`**: Maps tool names to their file path argument:

| Tool | Arg key |
|---|---|
| `read`, `write`, `edit`, `patch` | `args.filePath` |
| `bash` | Parse `cat <file>` or `less <file>` from `args.command` |
| Other tools | `undefined` (no file path extraction) |

---

## Testing — `tests/`

### Test Framework

Tests use **Bun's built-in test runner** (`bun:test`). No additional test framework is needed.

### `tests/config.test.ts`

Tests configuration defaults and Zod schema validation:

- Default config has all 11 categories
- `pii-ip-address` is disabled by default
- All other categories are enabled
- Blocked file paths contain expected patterns
- Env strip patterns contain expected entries
- LLM is disabled by default, debug is enabled
- Zod validates empty configs, partial configs, custom patterns
- Zod rejects invalid categories, negative `maxTokens`, non-integer `maxTokens`
- Action mode defaults: `safetyEvaluator.actionMode === "block"`, `outputSanitizer.actionMode === "redact"`
- Zod validates all valid action mode values
- Zod rejects invalid action mode values

### `tests/hooks.test.ts`

Tests hook behavior with mock dependencies:

**Mock setup:**
```typescript
const mockClient: PluginClient = {
  app: { log: async () => undefined },
  tui: { showToast: async () => undefined },
}

function createTestDeps() {
  const engine = createDetectionEngine(DEFAULT_CONFIG)
  const auditLogger = new AuditLogger(testAuditConfig) // disabled file logging
  const sessionStats = new SessionStats("test")
  const toastState: ToastState = { lastToastTime: 0, minInterval: 0 }
  const sessionAllowlist = new Set<string>()
  const evaluatedCalls = new Set<string>()
  return { engine, auditLogger, sessionStats, toastState, sessionAllowlist, evaluatedCalls }
}
```

**Input sanitizer tests:**
- Blocks `.env` file access (expects thrown error)
- Allows normal file access
- Redacts secrets in tool args (OpenAI key in bash command)
- Skips excluded tools (`glob`)
- Respects session allowlist (`.env` added to allowlist → not blocked)

**Output redactor tests:**
- Redacts secrets in output
- Redacts secrets in title
- Passes clean output unchanged

**Env sanitizer tests:**
- Redacts sensitive env var values
- Strips env vars matching name patterns
- Does nothing when disabled

**Compaction context tests:**
- Injects security policy context
- Context contains expected sections

### `tests/detection-patterns.test.ts`

Tests pattern detection across all categories:

- API keys: OpenAI, Anthropic, AWS, GitHub, Slack, Stripe, JWT, SendGrid, NPM, GCP
- Credentials: Password in URL, MongoDB/PostgreSQL/MySQL/Redis connection strings
- Private keys: RSA, OpenSSH, DSA, EC, PGP
- Docker: Swarm token
- Kubernetes: Client key data
- Cloud: Azure connection string, Vault token, DigitalOcean PAT
- PII: Email, US phone, SSN, credit card (with Luhn validation), IPv4 (public vs private)

### Writing New Tests

Follow these patterns:

```typescript
import { describe, test, expect } from "bun:test"

describe("Feature Name", () => {
  test("describes what should happen", async () => {
    // Arrange
    const deps = createTestDeps()
    const hook = createSomeHook({ ...deps, config: DEFAULT_CONFIG, client: mockClient })

    // Act
    const input = { tool: "read", sessionID: "s1", callID: "c1" }
    const output = { args: { filePath: "/project/test.ts" } }
    await hook(input, output)

    // Assert
    expect(output.args.filePath).toBe("/project/test.ts")
  })
})
```

---

## Key Algorithms

### 1. Overlapping Match Resolution

When multiple patterns match overlapping text regions, the engine resolves conflicts:

```
Input: "Bearer sk-proj-abc123..."

Pattern A: "Bearer Token" matches "Bearer sk-proj-abc123..."  (30 chars, medium confidence)
Pattern B: "OpenAI Key"   matches "sk-proj-abc123..."          (20 chars, high confidence)

These overlap at "sk-proj-abc123..."

Resolution:
1. Sort by start position
2. Pattern A starts earlier, so it's checked first
3. Pattern B overlaps with A (B.start < A.end)
4. Pattern A is longer (30 > 20), so A wins
5. Result: Only Pattern A's match is kept
```

### 2. Deep Recursive Object Scanning

Tool arguments can be nested objects or arrays:

```json
{
  "command": "echo sk-proj-xxxx",
  "env": {
    "API_KEY": "sk-proj-yyyy",
    "nested": {
      "deep": "sk-proj-zzzz"
    }
  },
  "args": ["sk-proj-aaaa", "safe-value"]
}
```

`deepScan()` walks this structure recursively, scanning each string value and producing a redacted copy. The depth limit (10) prevents stack overflow.

### 3. Toast Rate Limiting

```typescript
function canToast(state: ToastState): boolean {
  const now = Date.now()
  if (now - state.lastToastTime < state.minInterval) return false
  state.lastToastTime = now
  return true
}
```

This is a simple time-windowed rate limiter. The `ToastState` object is shared across all hooks, so a toast from the input sanitizer prevents a toast from the output redactor if they fire within the same 2-second window.

### 4. Configuration Deep Merge

```typescript
function deepMerge(target, source) {
  const result = { ...target }
  for (const key of Object.keys(source)) {
    if (isObject(source[key]) && isObject(result[key])) {
      result[key] = deepMerge(result[key], source[key])  // Recurse
    } else if (source[key] !== undefined) {
      result[key] = source[key]  // Override
    }
  }
  return result
}
```

Arrays are replaced entirely (not concatenated). This is intentional — if a user specifies `blockedFilePaths: [".env"]`, they want exactly that list, not the defaults plus `.env`.

### 5. Permission-to-InputSanitizer Deduplication

```
permission.ask fires for tool X:
  → evaluates safety
  → adds callID to evaluatedCalls
  → sets permission status

tool.execute.before fires for tool X:
  → checks evaluatedCalls.has(callID) → true
  → skips safety evaluation entirely
```

Without this, the same tool call would be evaluated twice by the LLM (once in `permission.ask`, once in `tool.execute.before`), wasting time and potentially producing inconsistent results.

### 6. Luhn Checksum Validation

Used for credit card number validation (`src/detection/patterns/pii.ts`):

```typescript
function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, "")
  let sum = 0
  let alternate = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10)
    if (alternate) {
      n *= 2
      if (n > 9) n -= 9
    }
    sum += n
    alternate = !alternate
  }
  return sum % 10 === 0
}
```

This reduces false positives — random 16-digit numbers that don't pass Luhn are not redacted.

---

## Error Handling Philosophy

The plugin follows a **fail-open, log-and-continue** philosophy for non-critical operations:

### Critical Operations (can throw)

- **File path blocking**: Throws `Error` to prevent tool execution. The AI sees the error message.
- **Safety evaluation blocking**: Throws `Error` with risk details. The AI sees why the command was blocked.

### Non-Critical Operations (catch and continue)

- **Toast notifications**: Wrapped in `try/catch` — toast failures never break tool execution
- **LLM calls**: Caught and defaulted to safe "allow" responses — LLM unavailability doesn't block all tools
- **Audit logging**: Caught silently — logging failures don't affect tool execution
- **Health checks**: Non-blocking, caught and logged — unhealthy LLM falls back to regex-only

### Pattern: `catch { /* toast failure is non-critical */ }`

This pattern appears frequently throughout the codebase. The empty catch is intentional — toast failures are truly non-critical and logging them would create noise.

### Pattern: Fail-Open LLM

Both the `SafetyEvaluator` and `LlmSanitizer` return safe/unchanged defaults when the LLM fails:

```typescript
// SafetyEvaluator.evaluate()
catch (err) {
  return { safe: true, riskLevel: "none", ..., recommendation: "allow" }
}

// LlmSanitizer.sanitize()
catch (err) {
  return { sanitized: rawOutput, detections: [] }  // Return unchanged output
}
```

This ensures the plugin never becomes a point of failure — if the LLM is down, regex-only mode continues working.

---

## Adding New Features

### Adding a New Detection Pattern

1. Choose the appropriate file in `src/detection/patterns/`
2. Add a `DetectionPattern` to the exported array:

```typescript
{
  id: "my-service-api-key",           // Unique ID, kebab-case
  name: "My Service API Key",         // Human-readable name
  category: "api-keys",               // Must be a PatternCategory value
  pattern: /myservice_[A-Za-z0-9]{32}/g,  // Regex with /g flag
  redact: () => "[REDACTED]",         // Redaction function
  confidence: "high",                 // low, medium, or high
}
```

3. Add a test in `tests/detection-patterns.test.ts`:

```typescript
test("detects My Service API key", () => {
  const result = engine.scan("key is myservice_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345")
  expect(result.hasDetections).toBe(true)
  expect(result.matches[0].patternId).toBe("my-service-api-key")
})
```

4. Run `bun test` to verify

### Adding a New Pattern Category

1. Add the category to `PatternCategory` in `src/types.ts`
2. Add to `patternCategorySchema` in `src/config/schema.ts`
3. Add default enabled/disabled to `DEFAULT_CONFIG.categories` in `src/config/defaults.ts`
4. Add to `detectionsByCategory` initialization in `src/audit/session-stats.ts`
5. Create a new pattern file in `src/detection/patterns/`
6. Import and spread into `ALL_BUILTIN_PATTERNS` in `src/detection/patterns/index.ts`
7. Add tests

### Adding a New Hook

1. Create a new file in `src/hooks/` following the factory pattern:

```typescript
interface MyHookDeps {
  config: SecurityGuardConfig
  client: PluginClient
  // ... other dependencies
}

export function createMyHook(deps: MyHookDeps) {
  const { config, client } = deps

  return async (
    input: { /* hook input type from SDK */ },
    output: { /* hook output type from SDK */ },
  ) => {
    // Implementation
  }
}
```

2. Import and create in `src/index.ts`
3. Register in the returned hooks object
4. Add tests in `tests/hooks.test.ts`

### Adding a New Custom Tool

1. Create a new file in `src/tools/`:

```typescript
interface MyToolDeps {
  // dependencies from index.ts
}

export function createMyTool(deps: MyToolDeps) {
  return {
    description: "Tool description for the AI",
    args: { /* arg definitions */ },
    async execute(args: { /* typed args */ }): Promise<string> {
      // Implementation — return text for AI
    },
  }
}
```

2. Import and create in `src/index.ts`
3. Register in the `tool` section using `tool()` from `@opencode-ai/plugin`

### Adding a New Action Mode

1. Add the mode value to the type in `src/types.ts`
2. Add to the Zod enum in `src/config/schema.ts`
3. Update the default in `src/config/defaults.ts`
4. Implement the behavior in the relevant hook
5. Add tests for the new mode

---

## Code Conventions

### Import Style

```typescript
import type { SomeType } from "../types.js"  // Type-only imports use `import type`
import { someFunction } from "../utils.js"     // Value imports use `import`
```

All imports use the `.js` extension (required by ESM with `moduleResolution: bundler`).

### Factory Pattern for Hooks

All hooks use the factory pattern: a function that accepts dependencies and returns the hook handler. This enables:
- Dependency injection (testability)
- Closure over shared state
- Clear separation of initialization and execution

### Naming Conventions

| Element | Convention | Example |
|---|---|---|
| Files | kebab-case | `input-sanitizer.ts` |
| Types/Interfaces | PascalCase | `SecurityGuardConfig` |
| Functions | camelCase | `createInputSanitizer` |
| Constants | UPPER_SNAKE or camelCase | `RISK_LEVEL_ORDER`, `DEFAULT_CONFIG` |
| Pattern IDs | kebab-case | `openai-api-key` |
| Config keys | camelCase | `blockThreshold` |

### Error Handling Pattern

```typescript
// Critical — throw to block
throw new Error(`Security Guard: ${explanation}`)

// Non-critical — catch and continue
try {
  await client.tui.showToast({ ... })
} catch { /* toast failure is non-critical */ }

// LLM failure — fail open
try {
  const result = await safetyEvaluator.evaluate(tool, args)
} catch {
  return { safe: true, riskLevel: "none", recommendation: "allow" }
}
```

### Debug Logging Pattern

```typescript
const debugLog = config.llm.debug
  ? (msg: string) => {
      client.app.log({
        body: { service: "security-guard", level: "info", message: msg },
      }).catch(() => {})
    }
  : undefined

debugLog?.(`Some debug message: ${variable}`)
```

The `debugLog` is a nullable function created once per hook. When debug is disabled, it's `undefined` and the optional chaining `?.` makes calls no-ops with zero overhead.

### Toast Messages

Toast messages follow a consistent format:
- Blocked: `🛡 Blocked: {reason}`
- Redacted: `🔒 Redacted {count} secret(s) in {tool} output`
- Warning: `⚠️ Warning: {explanation}`
- Info: `⚠️ Detected {count} secret(s) (NOT redacted)`
