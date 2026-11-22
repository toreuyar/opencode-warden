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
- **OpenCode** 2.0.18+ — supported host floor (below-floor 2.x runtimes warn but keep protections active; typed `Tool.Error` vetoes require 2.0.29+)

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
| `@opencode/plugin` | Peer/Dev | OpenCode V2 plugin SDK. The peer range is `^2.0.18` (the API floor Warden's used surface is verified against); the installed dev dependency stays `^2.1.4` for type-checking against the latest 2.x SDK. The SDK is not the host; the runtime version gate uses `ctx.app.version`. |
| `@types/bun` | Dev | Bun runtime type definitions |
| `typescript` | Dev | TypeScript compiler |

---

## Directory Structure

```
src/
├── index.ts                         # Plugin.define setup(ctx): config, state, hook wiring, tools
├── types.ts                         # All shared TypeScript type definitions
├── rpc.ts                           # Public notification RPC contract (event-only)
├── tui.ts                           # TUI companion entrypoint (no enforcement)
├── tui-notifications.ts             # Server-side notification bridge (wired in index.ts)
│
├── config/
│   ├── index.ts                     # Defaults → global → project, inline fallback, failure signal
│   ├── defaults.ts                  # Hardcoded default configuration values
│   └── schema.ts                    # Zod validation schemas
│
├── detection/
│   ├── index.ts                     # Public API: createDetectionEngine()
│   ├── engine.ts                    # Core DetectionEngine class (scan, overlap resolution)
│   ├── redactor.ts                  # Redaction helper functions
│   └── patterns/                    # Built-in pattern families (65 active by default)
│
├── hooks/
│   ├── input-sanitizer.ts           # tool.execute.before — input scanning and safety eval
│   ├── output-redactor.ts           # tool.execute.after — output redaction
│   ├── permission-handler.ts        # permission.evaluate — permission integration
│   ├── env-sanitizer.ts             # shell.create.before — environment sanitization
│   ├── shell-backstop.ts            # shell.create.before — global path backstop
│   ├── outbound-sanitizer.ts        # session.context/generate/title — policy + outbound text scan
│   ├── compaction-context.ts        # session.compaction — compaction request scan
│   ├── prompt-sanitizer.ts          # session.prompt — opt-in prompt/attachment metadata scan
│   ├── session-permissions.ts       # session deny-rule translation/sync
│   ├── tool-surface.ts              # blockedTools removal from request/transform surfaces
│   ├── session-context.ts           # Session TTL sweep helpers
│   ├── v2-adapters.ts               # V2 event adapters + fail-closed lockdown
│   └── security-policy.ts           # Builds security policy text for request context
│
├── llm/
│   ├── index.ts                     # LlmSanitizer + module re-exports
│   ├── client.ts                    # HTTP client for LLM API (fetch-based)
│   ├── context.ts                   # ConversationContext — sliding window history
│   ├── prompts.ts                   # System prompts, templates, renderTemplate()
│   ├── safety-evaluator.ts          # SafetyEvaluator class (12-dimension risk assessment)
│   ├── shell-complexity.ts          # Optional command-only composition precheck
│   ├── payload-decode.ts            # Deterministic pre-decoding of encoded payloads
│   ├── static-findings.ts           # Credential-surface + verdict-forgery detection
│   └── command-annotations.ts       # Tool-semantics annotations (tar/dc/gdb)
│
├── audit/
│   ├── index.ts                     # AuditLogger orchestrator
│   ├── file-logger.ts               # File-based logging with buffering and rotation
│   └── session-stats.ts             # In-memory session statistics and timeline
│
├── tools/                           # 7 custom tools (help, dashboard, report, audit,
│                                    # evaluate, config, rules)
│
└── utils/
    ├── paths.ts                     # Glob matching, file-target extraction, exemptions
    ├── tool-compat.ts               # V1/V2 tool-name + argument aliases
    └── deep-scan.ts                 # Recursive object/array scanning for secrets

scripts/
├── llm-harness.ts                   # LLM evaluation test harness (standalone CLI)
├── llm-harness-tests.json           # 237-test suite (generated from WARDEN_LLM_TESTS.md)
├── llm-harness.config.example.json  # Example harness config (real config is gitignored)
├── run-full-suite.sh                # Multi-model full-suite runner
└── LLM_HARNESS.md                   # Harness documentation

tests/
├── config.test.ts                   # Configuration defaults and Zod schema validation
├── config-source.test.ts            # Inline/file precedence + fail-closed failures
├── hooks.test.ts                    # Internal handler behavior (input, output, env, compaction)
├── fail-closed-evaluator.test.ts    # Evaluator outage/null-component regressions
├── detection-patterns.test.ts       # Pattern detection tests across all categories
├── payload-decode.test.ts           # Payload decoder + prompt integration tests
├── v2-*.test.ts                     # V2 adapters, native hooks, session policy
├── tui-notifications.test.ts        # RPC contract, bridge, TUI rendering
└── warden-fixes.test.ts             # Bypass-gate + ground-truth injection regressions
```

---

## Architecture Overview

Warden is a layered interception system built on the V2 plugin API. All bridging from V2 events to the internal V1-shaped handlers lives in `src/index.ts` and `src/hooks/v2-adapters.ts`.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        OpenCode V2 Runtime                          │
│                                                                     │
│  User prompt → AI agent → Tool call → [Plugin Hooks] → Tool exec   │
│                    ↓                                                │
│         Provider request built per turn                             │
└──────────────┬───────────────────────────────────┬──────────────────┘
               │                                   │
               ▼                                   ▼
┌──────────────────────────┐    ┌──────────────────────────────────┐
│     src/index.ts         │    │    V2 domain hooks               │
│  Plugin.define setup(ctx)│───▶│                                  │
│  - Config loading        │    │ session.prompt                   │
│  - Failure lockdown      │    │ session.context                  │
│  - Component init        │    │ session.generate                 │
│  - Hook registration     │    │ session.title                    │
│  - Tool transform        │    │ tool.execute.before              │
│  - Session lifecycle     │    │ shell.create.before              │
└──────────────────────────┘    │ permission.evaluate              │
                                │ tool.execute.after               │
                                │ session.compaction               │
                                └───────────┬──────────────────────┘
                                            ▼
        ┌───────────────────────────────────────────────────┐
        │              Shared Dependencies                   │
        │                                                    │
        │  DetectionEngine ◄─── Pattern Registry             │
        │  SafetyEvaluator ◄─── ProviderChain + Prompts      │
        │  LlmSanitizer   ◄─── ProviderChain + Context       │
        │  AuditLogger     ◄─── FileLogger                   │
        │  SessionStats    ◄─── Timeline tracking             │
        │  ToastState      ◄─── Rate limiter (UX only)         │
        │  evaluatedCalls  ◄─── Set<string> (deduplication)   │
        │  sessionAllowlist◄─── Set<string> (exact overrides) │
        └───────────────────────────────────────────────────┘
```

### Data Flow Summary

1. **Configuration** loads from defaults → global file → project file (deep merge). Inline `ctx.options` is used only when neither file exists. Any invalid/unreadable present source produces a `failure` and an active deny-all lockdown.
2. **Detection engine** is built from enabled categories + disabled patterns + custom patterns.
3. **LLM components** are conditionally initialized if `llm.enabled` is true. If enabled but unavailable, evaluation/sanitization fails closed regardless of action mode.
4. **Hooks** are created as closures over per-session state and registered on V2 domains in `setup(ctx)`.
5. **A tool call** flows through `tool.execute.before` (authoritative), optional `shell.create.before`, optional `permission.evaluate`, execution, then `tool.execute.after`.
6. **Every primary provider dispatch** passes through `session.context` for policy injection, blocked-tool removal, and outbound redaction. `session.generate` receives the same treatment; the tool-less `session.title` request is redacted without policy injection; compaction has its own request hook.
7. **Session events** reset mutable state and invalidate the session deny-rule cache.

Cross-plugin hook order is registration order; there is no priority API. Warden cannot make its mutations final against a later plugin. Treat the host and all plugins as trusted, and load Warden last where possible.

### V2 Capabilities Intentionally Not Used

| Capability | Why Warden does not use it |
|---|---|
| `ctx.storage` | Audit files plus in-memory session state already cover persistence. Silent state migration and a second source of truth are not wanted. |
| Tool namespacing (`editor.namespace`) | Stable names (`security_dashboard`, etc.) are documented and used by existing workflows; renaming is cosmetic and breaks compatibility. |
| Tool progress/cancel | Marginal value for short policy checks; adds lifecycle surface without security benefit. |
| `ctx.generate.text` for safety evaluation | Evaluation deliberately uses Warden's independent, fail-closed provider chain. Coupling safety to the host's model routing would make an outage or routing change a bypass. |
| Plugin RPC methods | The notification RPC is event-only (`methods: {}`). Warden exposes no callable RPC that could influence enforcement. |
| Renaming tool-call keys/ids or rewriting provider-signed/encrypted text outbound | Warden structurally redacts historical tool-call input string values in the request projection but preserves keys/ids and never rewrites provider-signed/encrypted text; a required rewrite aborts the request. |
| Refusing to load on an old runtime | A failed setup drops every hook and leaves the host unprotected, so Warden warns and keeps enforcing. |

---

## Plugin Entry Point — `src/index.ts`

**Lines**: ~915 | **Exports**: default (`Plugin.define`), version-diagnostic helpers

This is the file OpenCode loads. It uses the V2 plugin shape:

```typescript
export default Plugin.define({
  id: "opencode-warden",
  async setup(ctx) {
    // ...
  },
})
```

`ctx.location.directory` is the workspace/project directory. `ctx.options` is the plugin-options record. The security modules still use internal `(input, output)`-shaped handlers; V2 adaptation lives in `src/hooks/v2-adapters.ts` and thin closures in `setup`.

### Initialization Sequence

1. **Construct a V1-shaped `PluginClient` shim** for the internal modules:
   - `app.log` → console (V2 has no structured `app.log` API)
   - `session.prompt` → `ctx.session.synthetic` (used only for permission-denial text)
   - `tui.showToast` → `createWardenNotificationBridge(...).showToast` (sanitized RPC event; UX only)
2. **Load configuration** via `loadConfig(directory, { inlineConfig: ctx.options })`.
   - On a loader exception or non-null `failure`, call `registerFailClosedHooks(ctx, ...)` and return a no-op cleanup. Do **not** construct a detection engine, audit logger, provider chains, normal hooks, or custom tools on this path.
3. **Create the detection engine**, resolve audit/diagnostic paths, and construct `AuditLogger`, `DiagnosticLogger`, and `LlmChatLogger`.
4. **Initialize LLM components** if `config.llm.enabled`: provider chains, `LlmSanitizer`, `SafetyEvaluator`, optional triage evaluators. Health checks are non-blocking; failures do not delay setup.
5. **Create shared per-session state** via `createSessionState()` / `getSessionState()`: stats, toast state, allowlist, evaluated calls, written-file registry, sanitizer, evaluator, last-access time.
6. **Create hook handlers** with dependency injection (`inputSanitizer`, `outputRedactor`, `envSanitizer`, `promptSanitizer`, `permissionHandler`, `outboundSanitizer`, `compactionContext`, `shellBackstop`).
7. **Create the session permission sync coordinator** (`createSessionPermissionSync`) using `ctx.session.get` / `ctx.session.update` when available.
8. **Create the 7 custom tool definitions** and register startup diagnostics, runtime warning, and session state sweep.
9. **Subscribe to events** (`session.created`, `session.deleted`, `session.permissions`) with an `AbortController`.
10. **Register V2 hooks** (order matters within Warden):
    - `session.context` → remove blocked request tools, append policy + outbound scan
    - `session.generate` → same policy, blocked-tool removal, and outbound scan
    - `session.title` → outbound redaction without policy injection
    - `tool.execute.before` → lazy session deny sync, then input sanitizer
    - `tool.execute.after` → execute-after adapter
    - `permission.evaluate` → lazy deny sync, then permission adapter
    - `shell.create.before` → shell backstop, then env sanitizer
    - `session.compaction` → compaction adapter
    - `session.prompt` → prompt sanitizer (text + attachment metadata)
11. **Register tools** with `ctx.tool.transform`: `editor.add(...)` for each tool, then `removeBlockedTransformTools(editor, config)`.

### Hook Registration Shape

```typescript
await ctx.session.hook("context", async (event) => {
  removeBlockedRequestTools(event.tools, config)
  await outboundSanitizer(event)
})

await ctx.session.hook("generate", async (event) => {
  removeBlockedRequestTools(event.tools, config)
  await outboundSanitizer(event, { surface: "generate" })
})

await ctx.session.hook("title", async (event) => {
  await outboundSanitizer(event, { surface: "title", appendPolicy: false })
})

await ctx.tool.hook("execute.before", async (event) => {
  await sessionPermissionSync.sync(event.sessionID)
  await inputSanitizer(
    { tool: event.tool, sessionID: event.sessionID, callID: event.id },
    { args: asRecord(event.input) },
  )
})

const permissionAdapter = createPermissionAdapter(permissionHandler)
await ctx.permission.hook("evaluate", async (event) => {
  await sessionPermissionSync.sync(event.sessionID)
  return permissionAdapter(event)
})

await ctx.shell.hook("create.before", async (event) => {
  await shellBackstop({ command: event.command, cwd: event.cwd })
  await envSanitizer({ cwd: event.cwd }, { env: event.env })
})
```

There is no returned hook object in V2. `setup()` returns only an optional cleanup function.

### Design Decisions

- **Policy injection is per request, not synthetic history.** `session.context` and `session.generate` append the policy to the request-local `event.system`; compaction does the same. `session.title` intentionally opts out because it is a narrow tool-less naming request. This avoids history pollution and marker-forgery dedup problems.
- **Config failure is an active lockdown.** A failed `setup()` would drop every Warden hook, so config failures install deny/withhold hooks and return normally instead.
- **Runtime version is a warning, not a gate.** Refusing activation on an old runtime would leave the host unprotected.
- **Shared mutable state is sequential.** `evaluatedCalls`, `sessionAllowlist`, and `toastState` are shared by reference; OpenCode runs hooks sequentially, so there is no concurrent access. Session permission sync is the only in-flight async cache and is race-safe.
- **Notifications never gate enforcement.** The server `showToast` shim routes through `src/tui-notifications.ts`, which emits a strict RPC event; registration or delivery failure is non-blocking. The TUI companion renders fixed copy and cannot influence decisions.

---

## Type System — `src/types.ts`

**Lines**: ~382 | **Purpose**: Central type definitions for the entire application

All shared types are defined in one file for simplicity and import convenience. Local factory dependency interfaces and V2 event/adaptor structural types live next to their handlers. The key type hierarchies:

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
├── diagnosticLog: diagnosticLogSchema
├── env: envSanitizerSchema
├── indirectExecution: indirectExecutionSchema
└── llm: llmConfigSchema
      ├── outputSanitizer: llmOutputSanitizerSchema
      │     └── actionMode: outputActionModeSchema  ← z.enum(["redact", "warn", "pass"])
      ├── outputTriage/outputTextTriage: endpoint schemas
      └── safetyEvaluator: llmSafetyEvaluatorSchema
            └── actionMode: safetyActionModeSchema  ← z.enum(["block", "permission", "warn"])
```

**Validation rules of note:**
- `baseUrl` uses `z.string().url()` — requires valid URL format
- `temperature` uses `z.number().min(0).max(2)` — LLM temperature range
- `maxTokens` uses `z.number().int().min(1)` — must be a positive integer
- Pattern categories use `z.enum([...])` — rejects unknown categories
- The schema is intentionally non-strict: unknown keys are stripped (forward compatibility). Known keys with invalid types/values are hard failures
- File and inline sources use the exact same schema

The inferred type `SecurityGuardUserConfig` is what the schema produces. It has all fields as optional, unlike `SecurityGuardConfig` which has all fields as required (filled by defaults).

### `config/defaults.ts` — Default Values

Contains `DEFAULT_CONFIG: SecurityGuardConfig` with every field filled in. Key defaults:

- All categories enabled except `pii-ip-address` (disabled due to false positives): 65 active patterns from 66 defined
- 28 blocked file patterns (`.env`, `*.pem`, `*.key`, kubeconfig, tfstate, Warden config, etc.)
- 1 write-protected pattern (`**/var/log/**`)
- `excludedTools: []` (V2 has no obsolete `list` tool)
- 24 env strip patterns (`*_SECRET`, `*_TOKEN`, `AWS_SECRET_ACCESS_KEY`, etc.)
- LLM disabled by default, debug logging enabled
- Safety evaluator tools: `["shell", "write", "edit", "patch", "read", "webfetch"]`, `actionMode: "block"`, `blockThreshold: "high"`, `warnThreshold: "medium"`
- Output sanitizer tools: `["read", "shell", "grep"]`, `actionMode: "redact"`
- Audit: enabled, 10MB max file, 5 rotated files, `"normal"` verbosity

### `config/index.ts` — Loading, Fallback, and Failure

`loadConfig(projectDir, options?)` returns `{ config, warnings, failure }` — not just a config object.

```typescript
const { config, warnings, failure } = loadConfig(directory, {
  inlineConfig: ctx.options,
})
```

Precedence:

1. Defaults are always the base.
2. If the global config exists, load it.
3. If the project config exists, load it after global.
4. **If either file exists, inline `ctx.options` is ignored entirely** — even if the file is invalid or unreadable. A global path excluded by the test-only `skipGlobalConfig` is not a source.
5. Only when neither file path exists is inline config validated and merged over defaults.
6. Any invalid/unreadable present source returns a `failure` (`WARDEN_CONFIG_INVALID` / `WARDEN_CONFIG_UNREADABLE`, `failClosed: true`) and a fail-closed shell config (LLM enabled, empty provider chains). It does not fall back to a lower layer, defaults, or inline options.

`loadConfig` never throws for file/inline failures. The caller must inspect `failure` and install blocking hooks; the shell config alone is not sufficient. Failure diagnostics are sanitized: no configured values, and no JSON parser messages (they can echo document snippets containing secrets).

**`deepMerge(target, source)`** is a recursive merge function:
- Objects are merged recursively (key by key)
- Arrays are replaced entirely (not concatenated)
- `undefined` values in source are skipped
- `null` values in source overwrite target
- Primitives in source overwrite target

This means if a user specifies `blockedFilePaths: [".env"]`, it completely replaces the default list rather than appending to it. This is intentional — users can fully control which paths are blocked.

`normalizeConfiguredToolLists()` canonicalizes `bash`→`shell` and `task`→`subagent` in memory for `excludedTools`, `blockedTools`, and both LLM tool lists. It never rewrites the user's config files.

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

**Dependencies (production uses `getSessionState`; tests may pass individual state):**

```typescript
interface InputSanitizerDeps {
  engine: DetectionEngine
  config: SecurityGuardConfig
  auditLogger: AuditLogger
  projectDir?: string
  client: PluginClient
  diagnosticLogger: DiagnosticLogger | null
  getSessionState?: (sessionID: string) => {
    sessionStats: SessionStats
    safetyEvaluator: SafetyEvaluator | null
    toastState: ToastState
    sessionAllowlist: Set<string>
    evaluatedCalls: Set<string>
    writtenFileRegistry: Map<string, WrittenFileMetadata>
  }
  // Optional individual state for tests
  sessionStats?: SessionStats
  safetyEvaluator?: SafetyEvaluator | null
  toastState?: ToastState
  sessionAllowlist?: Set<string>
  evaluatedCalls?: Set<string>
  writtenFileRegistry?: Map<string, WrittenFileMetadata>
}
```

**Processing pipeline:**

**Step 0: Gates** — `blockedTools` throws; `excludedTools` skips this tool's input/output processing (global outbound context/generate/title/compaction scanning still applies); `sshOnlyMode` skips non-remote/non-shell calls. Tool names are compared with alias awareness (`shell`↔`bash`, `subagent`↔`task`).

**Step 1: Record tool call** — Increments the per-session tool call counter.

**Step 2: Check every file target** — `extractFileTargets(tool, args)` returns `{ path, mode }` targets for V2 `path`/legacy `filePath`, every `patchText` add/update/delete/move target, and shell redirections/reads. Each target is checked:
- session allowlist first (wins)
- `blockedFilePaths` for read and write
- `writeProtectedPaths` only for write
- dynamic shell targets (`$VAR`, backticks) fail closed before path checks

If blocked: audit log, notification attempt, `throw Error`. Without multi-target extraction, `echo >> authorized_keys` and patch moves would bypass the file blocker.

**Step 3: Regex deep scan** — Calls `deepScan(output.args, engine)` to recursively scan string values in the args object. Detections are replaced in-place (mutating `output.args`), unless `redactionEnabled`/`redactOnWrite`/`redactionExemptPaths` skip it. Category counts are recorded in session stats. A path-scoped exemption is all-or-nothing across every write target (e.g., a patch that updates an exempt file and moves it to a non-exempt path is still redacted).

**Step 4: LLM safety evaluation** — Runs if the tool is in `safetyEvaluator.tools`, is not bypassed, and the call id is not already in `evaluatedCalls`. If the LLM and component are enabled but the evaluator is `null`, the call fails closed. `evaluateFileExecution()` covers indirect script execution.

**Action mode logic:**
- `"block"`: `recommendation === "block"` or `evaluationFailed` → `throw Error`; `warn` → notification
- `"permission"`: falls back to `"block"` behavior if `permission.evaluate` did not fire (e.g., tool auto-allowed)
- `"warn"`: a genuine model `block` verdict may only warn, but `evaluationFailed` (outage/garbage) throws regardless

**Host veto mapping:** `@opencode/plugin` 2.0.29+ converts an `execute.before` rejection into a typed `Tool.Error`; on the supported 2.0.18–2.0.28 hosts the same throw aborts the call through the older untyped per-call rejection path exercised by the 2.0.18 runtime validation. Both prevent execution.

**Step 5: Audit log** — Records scan results, safety evaluation, and detection counts. Blocks are audited here because `tool.execute.after` does not run after a before-hook rejection.

### `hooks/output-redactor.ts` — `tool.execute.after`

**Purpose**: Redact secrets from tool output before the AI sees them.

**Processing pipeline:**

**Pass 1: Regex scan** — Scans `output.output`, `output.title`, and metadata through the detection engine. In `"pass"` mode, detections are counted but not redacted. In `"redact"` and `"warn"` modes, text is replaced.

**Pass 2: LLM sanitization** — Second pass using the LLM for context-aware detection. Skipped in `"pass"` mode, when `skipWhenRegexClean` is true and regex found nothing, or for deterministic output bypasses. If the LLM is enabled and the tool is in the sanitizer list but the sanitizer is missing/unavailable, output is withheld (`[BLOCKED]`) — never released raw. The single availability gate is intentional; do not re-add mid-pipeline `isAvailable()` skips.

**V2 adapter (`createExecuteAfterAdapter`)** — The adapter handles both `status: "completed"` and `status: "error"`:
- Scans textual `content`; if absent but structured `output` exists, serializes it and sanitizes the fallback.
- Writes sanitized text back to `content` and drops raw structured `output` when changed/blocked.
- Recursively redacts metadata (bounded depth, cycle/prototype guards), including keys/values.
- Resolves the model-visible error message (unwrap `.error` causes like OpenCode's `toSessionError`), scans it, then removes the cause so the raw nested value cannot surface later.
- Converts redactor exceptions into a fixed `[BLOCKED]` result.

**Notification behavior by action mode:**
- `"redact"`: Rate-limited notification with count/method
- `"warn"`: Always shows detailed notification (bypasses rate limiter)
- `"pass"`: Rate-limited detection notice saying "NOT redacted — pass mode"

### `hooks/env-sanitizer.ts` — `shell.create.before`

**Purpose**: Sanitize environment variables before shell commands see them.

**Two-strategy approach:**

1. **Value scanning**: Runs every env var's value through the detection engine. Secrets in values are redacted in-place.
2. **Name stripping**: Matches env var names against `stripPatterns` using glob patterns. Matching vars are replaced with `"[REDACTED]"` regardless of value. This catches vars like `MY_SECRET=anything` where the value might not match a regex.

**`matchEnvPattern()` helper**: Converts glob patterns to regex. Special characters are escaped, `*` becomes `.*`, and the pattern is anchored with `^...$`.

V2 runs this from `shell.create.before`, after `shell-backstop.ts`. It applies to every shell creation, not only agent tool calls.

### `hooks/shell-backstop.ts` — `shell.create.before`

**Purpose**: Deterministic global path backstop for every shell spawn.

- Parses `command` with `extractFileTargets("shell", ...)` and checks `blockedFilePaths`/`writeProtectedPaths`; whitelist wins.
- Resolves relative `cwd` against `ctx.location.directory`; absolute `cwd` is used as-is.
- Also checks remote SSH/SCP/rsync/rclone read/write paths.
- Makes no LLM calls and has no session identity (the event has none), so audit entries use empty session/call ids.
- Dynamic targets (`$VAR`, backticks) are skipped here; the agent-facing input sanitizer already fails closed on them.
- **User impact:** because the hook is process-wide, a configured blocked path also prevents the user's own terminals/background shells from reading or writing that path. This is deliberate and broader than agent-only policy.
- Throwing aborts shell creation (untyped shell-hook failure channel), which is fail-closed but not a clean typed veto.

### `hooks/permission-handler.ts` — `permission.evaluate`

**Purpose**: Integrate with OpenCode's permission system and produce a deny/ask/allow decision.

**When does it fire?** When the host asserts a permission evaluation for a tool action. It is skipped when a configured/session deny already applies, so `tool.execute.before` remains the universal gate.

**Processing:**

1. **Alias-aware action/resources/call id resolution** via `v2-adapters.ts`: `action`, `resources`, `source.id`, `source.messageID`, `effect`, `message`.
2. **Mode gate**: Only acts when `safetyActionMode === "permission"`. Other modes return immediately.
3. **Deterministic checks first**: `blockedTools`, every local target from args/resources, and remote paths are denied **before** `shouldEvaluate()` and before the null-evaluator gate. V2 `resources` are relative file paths for file actions, resolved against `projectDir`; for `shell`, resources are raw command strings parsed as commands. `subagent` resources are agent IDs, not paths.
4. **LLM evaluation**: failure denies immediately (does not fall through to `ask`).
5. **Status mapping**:
   - `block` / evaluator failure → `effect = "deny"` + denial `message`
   - `warn` → `effect = "ask"`
   - `allow` → no change
6. **Deduplication**: Successful allow/ask/deterministic-bypass outcomes record the call id in `evaluatedCalls`. Denied/failed evaluations are not recorded.
7. **Denial text**: The adapter writes `event.message`; the handler also sends a synthetic `session.prompt` message on deterministic denies.

**Why fall back to "block" in the input sanitizer?** When `actionMode === "permission"` but the permission hook did not fire (auto-allowed tool), the input sanitizer still enforces safety by falling back to `"block"` semantics.

### `hooks/outbound-sanitizer.ts` — `session.context`, `session.generate`, `session.title`

**Purpose**: Deterministic pre-provider enforcement for primary, auxiliary, and title model requests. `session.compaction` delegates to the same sanitizer through its own adapter.

- `session.context` appends the security policy as a stable system part on every invocation. No marker-based dedup (forgery-resistant); OpenCode builds `event.system` fresh per request, so this never pollutes stored history.
- `session.generate` reuses the full session context (agent, tools, system, messages). It gets the same policy append, blocked-tool removal, and deterministic scan as a primary request, with diagnostics attributed to `session.generate`.
- `session.title` is a tool-less `SessionRequest` (`system` + `messages` + options). It gets deterministic redaction but deliberately **not** policy injection, because extra instructions can change title output. A bounded 2.0.18 local-mock replay confirmed the title request sent `[REDACTED]`, had no policy, persisted `Replay Title`, and exited 0.
- Scans system text, message `text`/`reasoning`/`compaction`, and tool-result text/JSON string values. Reconstructs JSON values rather than mutating stored objects.
- Historical tool-call input strings are structurally redacted in the request projection: call ids, tool names, argument keys, and object/array shape are preserved; only detected string leaves change. A changed projection is assigned to the per-request `part.input`; the original object is not mutated.
- File/media identifiers are scanned read-only; a detection throws rather than rewriting a provider reference. Provider-signed/encrypted text or metadata-sensitive input is never rewritten; a required redaction aborts the request.
- Honors `redactionEnabled` (skip scanning but still append policy where applicable), `redactOnWrite`, and `redactionExemptPaths` for attributable inputs/results. Attribution is history/window-dependent and all-or-nothing.
- Any scanner exception, cyclic/excessive-depth input, argument-key detection, non-JSON string with a detection, or unsupported request shape throws out of the hook, aborting request preparation (fail-closed).
- Successful redactions emit one audit entry tagged with the surface (`context`, `generate`, `title`, or `compaction`).

**Limitations:** the host persists the original pre-hook tool-call input before Warden sees it, and this hook shapes only the outbound request; it does not scrub the session DB or UI/event state. Provider-native metadata is preserved, but signed/encrypted text cannot be rewritten. The title/generate replay used an isolated OpenCode 2.0.18 local mock through the root-`index.js` load form; it did not use an external provider, a 2.1.4 binary, or a live rendered TUI, and it is not a certification of any host version.

### `hooks/compaction-context.ts` — `session.compaction`

**Purpose**: Scan the outbound compaction request and append the security policy.

- Native path delegates to the same deterministic outbound scanner over `system`/`messages`/`tools`; `redactionEnabled=false` still appends policy but skips scanning.
- Preserves model options, message metadata, provider metadata, and tool-call identity.
- Unsupported shapes and scanner failures throw, aborting request preparation.
- The legacy `{ context: string[] }` sink is still accepted for V1-shaped tests/callers; it receives policy only.

### `hooks/prompt-sanitizer.ts` — `session.prompt`

**Purpose**: Opt-in scanning of user/subtask prompt text **and attachment metadata** before admission.

- Gated by `scanUserPrompts` (default `false`) and `redactionEnabled`.
- Scans text parts (skipping synthetic parts), subtask prompts, and attachment metadata: file `uri` (except inline `data:` content), `name`, `description`, `mention.text`; agent `name`/mention; skill `id`/`name`/mention.
- **Never reads attachment file contents.** No decoding, no content scan.
- On detection: records stats/audit, attempts a notification, then throws to abort admission. The prompt never persists and never reaches the model.
- The runtime TUI surfaces a generic `"Session error"` rather than the detailed reason.

### `hooks/session-permissions.ts` — Session Deny-Rule Sync

**Purpose**: Defense-in-depth translation of exactly representable policy into session-scoped deny rules.

- Literal `blockedTools` → deny rules for canonical and alias spellings.
- Literal absolute `blockedFilePaths` → deny for read (`read`/`glob`/`grep`) and write (`write`/`edit`/`patch`) actions.
- Literal absolute `writeProtectedPaths` → write actions only.
- Omitted: permission wildcards, configured glob/relative/`~`/`host:` paths, shell path policy, and anything whitelisted. For an absolute path inside the project directory, both the absolute and host-relative resource are emitted; outside the project only the absolute resource is emitted.
- `session.update({ permissions })` replaces the host ruleset, so the sync re-reads and appends. It re-reads once more immediately before writing and defers if the host ruleset changed; the API has no compare-and-set, so this narrows but does not eliminate the race. Read/update failures resolve `false`, log, and retry later; they never change an allow/deny decision.
- Synced on `session.created` (best effort), lazily before `tool.execute.before`/`permission.evaluate`, invalidated on `session.permissions`, and forgotten on delete/TTL sweep.

### `hooks/tool-surface.ts` — Blocked Tool Surface

- `session.context` and `session.generate` delete blocked tools from the per-request `event.tools` map before dispatch (alias-aware, by advertised key). `session.title` has no tools.
- `tool.transform` iterates `editor.list()` and removes blocked tools by their **effective id** (including namespaces), after Warden's custom tools are added, so a blocked custom tool is also removed.
- `excludedTools` is never used here: it means "skip this tool's input/output processing", not "hide the tool". Global outbound context/generate/title/compaction scanning still covers all messages.

### `hooks/security-policy.ts` — Policy Text Builder

**Purpose**: Build a compact markdown document that explains the security system to the AI.

The `buildSecurityPolicyContext()` function generates sections for:
- `[REDACTED]` permanence
- Active redaction switches and exempt paths (inline values the agent cannot read from the blocked config file)
- Blocked file paths (when non-empty)
- Write-protected paths (when non-empty)
- Blocked-command retry warning
- Output size limit (when configured)
- A pointer to `security_help` for the tool list

It intentionally does **not** list every tool description or category (tests enforce conciseness). The text is appended per request by `session.context` and `session.generate` and to compaction requests; it is not a synthetic message. `session.title` deliberately opts out to preserve title output.

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

**Generation cap (fail-closed)**: When `maxTokens` is set (default `32768` via `DEFAULT_MAX_TOKENS` in `config/index.ts`), it is sent as `max_tokens`. All three response paths — non-streaming JSON, JSON-returned-despite-`stream:true`, and SSE — check `finish_reason`. If it is `"length"` (the generation cap was hit), an error is thrown: an evaluation that cannot conclude within the budget is inconclusive, and inconclusive means blocked upstream (fail-closed). Set `maxTokens: 0` to omit the cap from requests.

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

Contains self-contained system prompts for safety evaluation, file execution, output sanitization, and command/text triage. Defaults use direct rules, explicit precedence, and short contrasting examples for small models. User templates primarily carry labeled evidence instead of repeating the system policy. Custom prompt/template overrides remain supported.

**`DEFAULT_SANITIZER_SYSTEM_PROMPT`**: Identifies sensitive strings in the current output only, with exact matches, JSON escaping, and non-overlapping occurrence counts. Context guides classification but cannot supply findings. Returns `{ needsSanitization, findings: [{ sensitive, category, occurrences }] }`; does not rewrite the output.

**`DEFAULT_SAFETY_SYSTEM_PROMPT`**: Judges effects rather than command names, with specific prohibitions overriding routine examples and operational profiles. Keeps five risk levels, twelve canonical dimension labels, decoded-data versus execution guidance, and untrusted-input boundaries. Returns `{ safe, riskLevel, riskDimensions, explanation, suggestedAlternative, recommendation }`. No filename-based test override.

**File execution and triage**: File evaluation follows the actual interpreter and execution flow. Command triage sees only the invocation; text triage inspects current output. Both triage prompts request sanitization when uncertain and forbid sensitive values in reasons.

The separate complexity precheck prompt lives in `llm/shell-complexity.ts`. It judges separability only, preserves dependencies, and cannot approve execution. Prompt compactness and mocked/unit tests do not establish live-model accuracy; model-backed regressions are needed when evaluating prompt quality.

**`renderTemplate(template, vars)`**: Simple `{{key}}` → value replacement using `String.replaceAll()`.

**`buildSanitizePrompt()` / `buildSafetyPrompt()`**: Build the user prompt by rendering the template with tool name, args/output, and optional context. Falls back to default templates if custom template is empty.

`buildSafetyPrompt()` also appends **deterministic ground-truth sections** computed in code (see the three modules below) — decoded payloads, tool-semantics annotations, and static findings. The philosophy: deterministic facts live in code, judgment lives in the LLM. This prevents the model from burning its token budget on manual decoding and from missing credential surfaces it is inconsistent at recognizing.

The shell sequence gate (`src/utils/shell-sequence.ts`) is separate from these prompt findings. It parses Bash without executing it and rejects adjacent top-level simple commands or pipelines separated by `;` or a command-ending newline. It does not traverse nested constructs, treat a pipeline as a list, infer shell-state dependencies, or rewrite the call. Unsupported syntax yields no finding from this rule and still goes through existing enforcement. The agent pre-execution hook runs it before both direct and indirect LLM evaluation; the permission-mode hook and evaluator dry run reuse it. The global user-shell backstop is unchanged.

The implemented complexity precheck (`src/llm/shell-complexity.ts`) is enabled
only by `llm.safetyEvaluator.complexityPrecheck.enabled` with the LLM and safety
component enabled. It defaults off and uses the safety provider chain. AST
candidate selection recognizes groups, substitutions, long conditional chains,
and multiple root statements. Only a command is sent, without history.
`callValidated()` accepts `continue` or `simplify` with a structural reason
present in the AST. `simplify` and provider/validation failures veto even in warn
mode; `continue` requires full evaluation rather than bypass/dedup approval.
The input hook runs it before indirect file evaluation. It is also used by the
permission hook and `dryRun()`. Fixed retry copy is emitted instead of model
reasoning, and the full evaluator never receives the precheck's reasoning.

### `llm/payload-decode.ts` — Deterministic Payload Decoder

Extracts and decodes encoded segments (base64 chains, hex/octal escapes, ROT13, bare hex literals) from tool-call arguments **before** the LLM sees them. The decoded plaintext is injected into the prompt as ground truth so the model never performs mental decoding (which spirals into token-counting loops on some model families).

Design rules:
- Base64 decoding is gated on an explicit decoder command being present (`base64 -d`, `openssl -d`) — kills false positives on ordinary long words
- Multi-stage chains decode repeatedly, capped at `MAX_DEPTH` (5); results capped at `MAX_SEGMENTS` (8)
- Round-trip validation rejects ordinary alphanumeric words that merely look like base64
- Non-printable results are reported as opaque (`result: ""`, `printable: false`) — never shown as text

**`formatDecodedSection()`** renders the `═══ PRE-DECODED PAYLOADS ═══` prompt section; empty string when nothing decoded.

### `llm/static-findings.ts` — Credential Surfaces + Verdict Forgery

Deterministic detection of two finding kinds in tool-call arguments:

- **credential-surface**: cloud/instance metadata endpoints (169.254.169.254, metadata.google.internal), kubelet port (10250), Docker socket, Kubernetes service-account paths, `/etc/shadow`, `~/.aws/credentials`, `~/.kube/config`, service-account key JSONs
- **verdict-forgery**: Warden-schema-shaped text embedded in arguments (`Safe: Yes`, `Risk Level:`, `Recommendation: allow`) — a prompt-injection marker, never a real verdict

Findings serve two purposes:
1. `hasStaticFindings()` disqualifies bypass in `SafetyEvaluator.isBypassed()` — a plain `cat` of a service-account token must never skip evaluation
2. `formatFindingsSection()` renders the `═══ STATIC FINDINGS ═══` prompt section as ground truth

### `llm/command-annotations.ts` — Tool-Semantics Annotations

Deterministic annotations for tool families whose semantics the LLM grinds on (measured on the harness: 732 s on `dc`, 246 s on `tar --checkpoint`, 171 s on `gdb -batch`):

- **tar**: `--checkpoint-action=exec=…` EXECUTES its payload at each checkpoint (executor present); plain `--checkpoint` only prints progress
- **dc**: `!` invokes a shell on the popped string (executor); `P`/`p` are print-only
- **gdb**: `-ex` with `shell`/`run`/`attach` executes; `-ex 'echo …'` is print-only

**`formatAnnotationSection()`** renders the `═══ COMMAND SEMANTICS ═══` prompt section; empty when no annotations.

### `llm/safety-evaluator.ts` — SafetyEvaluator Class

The `SafetyEvaluator` analyzes tool calls for safety risks.

**`isBypassed(tool, args)`**: Only applies to the canonical `shell` tool (legacy `bash` accepted). A command bypasses LLM evaluation only if it starts with a prefix in `bypassedCommands` (e.g., `"git status"`, `"ls"`, `"pwd"`) **and** none of the following disqualifiers match:

1. **Execution primitive** — `eval`, `sh -c`, `$(...)`, backticks, process substitution, `xargs`, wrapper-binary execution (`awk system()`, `perl -e`, `python3 -c`, …), `find -exec`
2. **Unquoted shell comment** (`hasUnsafeComment()` in `utils/command-patterns.ts`) — quote-aware check for `#` at string start or after unquoted whitespace; injection content rides on benign commands (`ls /tmp # IGNORE PREVIOUS SAFETY RULES`)
3. **Static findings** (`hasStaticFindings()`) — credential surfaces or verdict forgery

When bypass is disqualified, the command is force-evaluated by the LLM. Bare bypass-listed commands (e.g. `cat README.md`) still bypass.

**`shouldEvaluate(tool)`**: Returns true if the evaluator is enabled AND the tool is in the `tools` list (default: `["shell", "write", "edit", "patch", "read", "webfetch"]`; legacy `bash` is accepted as an alias).

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

**Response parsing** (`parseResponse()`): Extracts JSON from the LLM response using a regex `/\{[\s\S]*\}/`. This handles cases where the LLM wraps JSON in markdown code blocks. Falls back to `{ safe: false, riskLevel: "critical", recommendation: "block" }` if parsing fails.

**Fail-closed design**: If the LLM call fails (timeout, network error, parse error, missing/invalid risk level or recommendation), the evaluator returns a blocking result with `evaluationFailed: true`. Callers block/deny on that flag regardless of `warn`/`permission` mode. A genuine model verdict does not set the flag, so a real `block` may follow `warn`. A model `block`/`warn` recommendation is a floor and cannot be downgraded by a contradictory lower `riskLevel`.

### `llm/index.ts` — LlmSanitizer Class

The `LlmSanitizer` handles the second-pass output sanitization.

**`healthCheck()`**: Calls `checkLlmHealth()` and sets the `connected` flag. Uses a 5-second timeout (shorter than the normal request timeout).

**`shouldSanitize(tool)`**: Returns true if LLM is enabled, output sanitizer is enabled, and the tool is in the sanitizer's tool list.

**`sanitize(toolName, rawOutput, context?)`**: Similar flow to safety evaluation:
1. Build prompt with context (tool name, args, title)
2. Call LLM
3. Parse JSON response: `{ sanitized, detections[] }`
4. Return sanitized output with detection list

**Fail-closed**: Throws on LLM call failure — the caller (output redactor) withholds the output entirely if sanitization cannot be completed.

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

Warden registers 7 tools through `ctx.tool.transform(editor => editor.add(...))`: `security_help`, `security_dashboard`, `security_report`, `security_audit`, `security_evaluate`, `security_config`, and `security_rules`. The sections below detail the three original tools; the additional audit/evaluate/config/help tools follow the same factory + `execute(args): Promise<string>` shape.

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
2. Check whitelist first — if any whitelist entry matches a path candidate **exactly**, return `false` (not blocked)
3. Check blocklist — if any glob pattern matches, return `true` (blocked)
4. Return `false` (not blocked by default)

**Whitelist takes priority over blocklist.** `whitelistedPaths` entries are exact paths (absolute, `~`-prefixed, or cwd-relative), not globs. This allows:
- Block `**/.env*` (glob)
- Whitelist `/home/you/project/.env.example` (exact path)

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

**`extractFileTargets(tool, args)`**: Returns every `{ path, mode }` target a tool call names. This is the shared multi-target extractor used by the input, permission, output, outbound, and shell hooks.

| Tool | Targets |
|---|---|
| `read`/`write`/`edit`/`glob`/`grep` | V2 `args.path`, falling back to legacy `args.filePath`; mode depends on the tool/action |
| `patch` | Every `*** Add File:`, `*** Delete File:`, `*** Update File:`, and `*** Move to:` path in `args.patchText` (move destinations are writes; update sources are checked too) |
| `shell` (legacy `bash`) | Redirection/`tee`/`truncate`/`dd of=` writes, input-redirect and read-command reads, and `ssh -i` identity files |
| Unsupported tools | Empty array |

Dynamic shell targets (`$VAR`, backticks) are reported as dynamic so the agent-facing input sanitizer can fail closed.

**`extractRemoteFilePathsFromArgs(tool, args)`** handles SSH/SCP/rsync/rclone read/write paths. **`isRedactionExempt()`** matches local or `host:`-scoped exemptions. **`isPathBlockedForMode()`** combines `blockedFilePaths` (all modes) and `writeProtectedPaths` (write only), with the whitelist winning.

### `utils/tool-compat.ts`

V1→V2 vocabulary helpers:

- `bash` ↔ `shell`, `task` ↔ `subagent`
- V2 `path` wins over legacy `filePath`
- `isToolInList()` is alias-aware on both sides
- `normalizeToolList()` canonicalizes and dedupes configured tool lists in memory without rewriting files

`patch` is V2-only input shape (`patchText`); there is no legacy equivalent beyond `filePath` fallback for older callers/tests.

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
  const writtenFileRegistry = new Map<string, WrittenFileMetadata>()
  return {
    engine, auditLogger, sessionStats, toastState, sessionAllowlist,
    evaluatedCalls, writtenFileRegistry, diagnosticLogger: null,
    outputTriage: null, outputTextTriage: null,
  }
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
    const output = { args: { path: "/project/test.ts" } }
    await hook(input, output)

    // Assert
    expect(output.args.path).toBe("/project/test.ts")
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

This is a simple time-windowed rate limiter. The `ToastState` object is shared across all hooks, so a notification attempt from the input sanitizer prevents one from the output redactor if they fire within the same 2-second window. The entrypoint wires the shim to the RPC/TUI bridge, which keeps only a closed event kind and bounded metadata. Notifications are UX-only and never gate enforcement.

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
permission.evaluate fires for tool X:
  → evaluates safety
  → records the shared tool call id (event.source.id) in evaluatedCalls
  → sets effect/message

tool.execute.before fires for tool X:
  → checks evaluatedCalls.has(callID) → true
  → skips safety evaluation entirely
```

Without this, the same tool call would be evaluated twice by the LLM, wasting time and potentially producing inconsistent results. In the observed V2 order (`execute.before` → `permission.evaluate`), the input sanitizer may evaluate first, so a duplicate is possible; the input sanitizer remains the authoritative pre-execution gate, so this is a performance issue, not a bypass. Denied/failed evaluations are deliberately not recorded.

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

The plugin follows a **fail-closed** philosophy for LLM-dependent security operations, and a **log-and-continue** philosophy for non-critical operations:

### Critical Operations (can throw)

- **File path blocking**: Throws `Error` to prevent tool execution. The AI sees the error message.
- **Safety evaluation blocking**: Throws `Error` with risk details. The AI sees why the command was blocked.
- **LLM evaluation failures**: When the LLM is unreachable/misconfigured/returns garbage, the safety evaluator marks `evaluationFailed` and the caller blocks/denies regardless of action mode; the output sanitizer withholds output. Explicitly disabled LLM/components are deterministic-only and do not trigger outage blocking. This is fail-closed by design — a security plugin must block when it cannot evaluate.
- **Config failure**: The entrypoint installs deny-all/withhold-all hooks rather than throwing out of `setup()`. A failed setup would drop every hook and leave the host unprotected.
- **Outbound scanner failure**: `session.context`/`generate`/`title`/compaction throws, aborting request preparation rather than sending unsanitized history. Session/shell hooks have no typed failure channel, so this is an abort/defect, not a clean typed veto.

### Non-Critical Operations (catch and continue)

- **Notifications**: Wrapped in `try/catch` — notification failures never break tool execution. The RPC/TUI bridge is non-blocking and reports at most a fixed diagnostic.
- **Audit logging**: Caught silently — logging failures don't affect tool execution
- **Health checks**: Non-blocking, caught and logged

### Pattern: `catch { /* toast failure is non-critical */ }`

This pattern appears frequently throughout the codebase. The empty catch is intentional — toast failures are truly non-critical and logging them would create noise.

### Pattern: Fail-Closed LLM

Both the `SafetyEvaluator` and `LlmSanitizer` return blocking defaults when the LLM fails:

```typescript
// SafetyEvaluator.evaluate()
catch (err) {
  return {
    safe: false,
    riskLevel: "critical",
    recommendation: "block",
    evaluationFailed: true, // callers block regardless of actionMode
  }
}

// LlmSanitizer.sanitize()
catch (err) {
  throw new Error(`LLM sanitization failed: ${errMsg}`)  // Output withheld by caller
}
```

A security plugin must never degrade to permissive behavior when its evaluator is down. If the LLM is enabled but unreachable, all LLM-evaluated operations are blocked and all sanitized output is withheld — even in `warn`/`permission` mode. Explicit `llm.enabled: false` or an explicitly disabled component is the only deterministic-only path, and it attempts no LLM calls.

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

2. Import and create it in `src/index.ts`
3. Register it with the appropriate V2 domain in `setup(ctx)` (`ctx.tool.hook(...)`, `ctx.permission.hook(...)`, `ctx.shell.hook(...)`, `ctx.session.hook(...)`). There is no returned hook object in V2.
4. Add tests. Use `tests/v2-*.test.ts` for V2 event shapes; `tests/hooks.test.ts` covers the internal V1-shaped handlers.

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

2. Import and create it in `src/index.ts`
3. Register it inside `ctx.tool.transform((editor) => { editor.add({ name, description, input, execute }) })`. Do not use the V1 `tool()` map. Keep `removeBlockedTransformTools(editor, config)` at the end of the transform so a blocked custom tool is also removed.

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

// LLM failure — fail closed (block)
try {
  const result = await safetyEvaluator.evaluate(tool, args)
} catch {
  return { safe: false, riskLevel: "critical", recommendation: "block" }
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

Toast/notification copy follows a consistent format:
- Blocked: `🛡 Blocked: {reason}`
- Redacted: `🔒 Redacted {count} secret(s) in {tool} output`
- Warning: `⚠️ Warning: {explanation}`
- Info: `⚠️ Detected {count} secret(s) (NOT redacted)`

In the V2 entrypoint the copy above is routed to the TUI/RPC companion as a fixed, closed-class event; raw messages, paths, and explanations are discarded. The TUI renders fixed copy (server-plugin toasts do not exist). Audit and diagnostic logs remain the authoritative record, and notifications never affect enforcement.
