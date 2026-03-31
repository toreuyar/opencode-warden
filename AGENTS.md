# AGENTS.md — AI Coding Agent Guide

This document is written for AI coding assistants (Claude, GPT, Copilot, Cursor, etc.) that will be working on the OpenCode Warden codebase. It explains what this project is, how it's structured, what conventions to follow, and how to make changes correctly.

## What This Project Is

OpenCode Warden is a **plugin** for [OpenCode](https://opencode.ai), an AI-powered coding assistant. The plugin acts as a security layer that intercepts every tool call the AI makes — reading files, running shell commands, editing code — and:

1. **Blocks** access to sensitive files (`.env`, `*.pem`, `*.key`, etc.)
2. **Scans and redacts** secrets in tool inputs and outputs using 74 regex patterns
3. **Evaluates safety** of tool calls using an optional LLM (10 risk dimensions)
4. **Sanitizes** environment variables before they reach shell commands
5. **Logs** all security events to an audit trail

The plugin is loaded by the OpenCode runtime and registers **hooks** that fire at specific points in the tool execution lifecycle. It does NOT have a UI of its own — it communicates through OpenCode's toast notifications, log panel, and permission system.

## Tech Stack

| Component | Technology |
|---|---|
| Runtime | [Bun](https://bun.sh) |
| Language | TypeScript (strict mode) |
| Test Runner | Bun's built-in (`bun:test`) |
| Schema Validation | [Zod](https://zod.dev) |
| Plugin SDK | `@opencode-ai/plugin` |
| Module System | ESM (`import`/`export`) |
| Build | `bun build src/index.ts --outdir dist --target bun` |

## Commands

```bash
bun install          # Install dependencies
bun test             # Run all tests (157 tests)
bun run typecheck    # TypeScript type checking (tsc --noEmit)
bun run build        # Build for distribution
```

**Always run `bun run typecheck` and `bun test` after making changes.** Both must pass with zero errors.

## Project Structure

```
src/
├── index.ts                      # Plugin entry point — wires everything together
├── types.ts                      # ALL type definitions (single file)
│
├── config/
│   ├── index.ts                  # Config loading: defaults → global → project (deep merge)
│   ├── defaults.ts               # DEFAULT_CONFIG with every field filled in
│   └── schema.ts                 # Zod schemas for user config validation
│
├── detection/
│   ├── index.ts                  # createDetectionEngine() factory
│   ├── engine.ts                 # DetectionEngine class (scan, overlap resolution)
│   ├── redactor.ts               # Simple redaction helpers
│   └── patterns/
│       ├── index.ts              # Aggregates all patterns, applies category/disabled filters
│       ├── api-keys.ts           # 20 API key patterns
│       ├── credentials.ts        # 7 credential patterns
│       ├── private-keys.ts       # 7 private key patterns
│       ├── docker.ts             # 4 Docker patterns
│       ├── kubernetes.ts         # 6 Kubernetes patterns
│       ├── cloud.ts              # 16 cloud provider patterns
│       └── pii.ts                # 7 PII patterns (email, phone, SSN, credit card, IP)
│
├── hooks/
│   ├── input-sanitizer.ts        # tool.execute.before — blocks files, scans args, safety eval
│   ├── output-redactor.ts        # tool.execute.after — redacts secrets in output
│   ├── permission-handler.ts     # permission.ask — integrates with OpenCode permissions
│   ├── env-sanitizer.ts          # shell.env — strips secrets from environment variables
│   ├── compaction-context.ts     # session.compacting — injects security context
│   └── security-policy.ts        # Builds security policy markdown for AI context
│
├── llm/
│   ├── index.ts                  # LlmSanitizer class (output sanitization via LLM)
│   ├── client.ts                 # HTTP client for OpenAI-compatible APIs
│   ├── context.ts                # ConversationContext — sliding window message history
│   ├── prompts.ts                # System prompts, templates, renderTemplate()
│   └── safety-evaluator.ts       # SafetyEvaluator class (10-dimension risk assessment)
│
├── audit/
│   ├── index.ts                  # AuditLogger — orchestrates file + app logging
│   ├── file-logger.ts            # Buffered, rotating JSON-line file logger
│   └── session-stats.ts          # In-memory session statistics and timeline
│
├── tools/
│   ├── security-dashboard.ts     # security_dashboard tool
│   ├── security-report.ts        # security_report tool
│   └── rules-manage.ts           # security_rules tool (persists to config file)
│
└── utils/
    ├── paths.ts                  # Glob matching, file path extraction from tool args
    └── deep-scan.ts              # Recursive object scanning for secrets

tests/
├── config.test.ts                # Config defaults + Zod schema validation
├── hooks.test.ts                 # Hook behavior (input, output, env, compaction)
└── detection-patterns.test.ts    # Pattern detection across all categories
```

## Architecture at a Glance

The plugin entry point (`src/index.ts`) exports an async function that OpenCode calls on startup. It:

1. Loads config (defaults → `~/.config/opencode/opencode-warden.json` → `.opencode/opencode-warden.json`)
2. Creates a `DetectionEngine` from enabled patterns
3. Creates `AuditLogger`, `SessionStats`, optional `LlmSanitizer` and `SafetyEvaluator`
4. Creates hook handler closures that share state via dependency injection
5. Returns the hook handlers and custom tool definitions

**Data flow for every tool call:**

```
permission.ask (if OpenCode prompts user)
    → LLM safety eval → deny/ask/allow → mark callID evaluated
        ↓
shell.env (if shell command)
    → strip sensitive env vars by name → scan values
        ↓
tool.execute.before (always fires)
    → block sensitive file paths
    → regex deep-scan args → redact in-place
    → LLM safety eval (if not already evaluated) → block/warn/pass
        ↓
[tool executes]
        ↓
tool.execute.after (always fires)
    → regex scan output + title → redact
    → LLM sanitization (context-aware second pass)
    → audit log + toast
```

## Critical Concepts

### Hook System

All hooks follow the **factory pattern**: a `createXxx(deps)` function that takes a dependencies object and returns an `async (input, output) => void` closure. The closure closes over shared mutable state.

```typescript
interface InputSanitizerDeps {
  engine: DetectionEngine
  config: SecurityGuardConfig
  auditLogger: AuditLogger
  // ... more deps
}

export function createInputSanitizer(deps: InputSanitizerDeps) {
  const { engine, config, auditLogger } = deps
  return async (input, output) => {
    // hook logic here — has access to deps via closure
  }
}
```

**When adding or modifying hooks**, follow this pattern exactly. Do not use classes for hooks.

### Shared Mutable State

These objects are shared by reference across multiple hooks and reset on `session.created`:

| Object | Type | Shared Between | Purpose |
|---|---|---|---|
| `toastState` | `ToastState` | input-sanitizer, output-redactor, env-sanitizer | Rate-limit toasts (2s window) |
| `sessionAllowlist` | `Set<string>` | input-sanitizer | Temporary file access overrides (config-based whitelistedPaths) |
| `evaluatedCalls` | `Set<string>` | permission-handler, input-sanitizer | Dedup between permission.ask and tool.execute.before |
| `policyInjected` | `boolean` | index.ts tool.execute.before wrapper | Track if security policy was injected |

**All hooks run sequentially** within OpenCode's event loop. There is no concurrent access to shared state.

### Configuration Hierarchy

```
Built-in defaults (src/config/defaults.ts)
    ↓ deep merge
Global config (~/.config/opencode/opencode-warden.json)
    ↓ deep merge
Project config (.opencode/opencode-warden.json)
```

The `deepMerge()` function in `src/config/index.ts`:
- Objects merge recursively (key by key)
- Arrays are **replaced entirely** (not concatenated)
- `undefined` values in source are skipped
- Primitives overwrite

This means user config files only need to specify overrides. The Zod schema makes every field optional.

### Error Handling Philosophy

**Two categories:**

1. **Critical (can throw)**: File path blocking and safety evaluation blocking. These throw `Error` to prevent tool execution. The error message is visible to the AI.

2. **Non-critical (catch and continue)**: Toast notifications, LLM calls, audit logging. These use `try/catch` with empty catches or return safe defaults.

**LLM components are fail-open**: If the LLM is unavailable, safety evaluator returns `{ safe: true, recommendation: "allow" }` and output sanitizer returns the original text unchanged. This prevents the plugin from becoming a single point of failure.

Pattern you will see frequently:
```typescript
try {
  await client.tui.showToast({ ... })
} catch { /* toast failure is non-critical */ }
```

This is intentional. Do not add error logging to these catches.

### Action Modes

Two configurable action modes control behavior:

**Input safety (`llm.safetyEvaluator.actionMode`):**
- `"block"` (default): Throw Error to block dangerous calls
- `"permission"`: Use OpenCode's permission system — auto-deny critical, prompt user for medium/high
- `"warn"`: Show toast but allow call to proceed

**Output sanitization (`llm.outputSanitizer.actionMode`):**
- `"redact"` (default): Auto-redact secrets in output
- `"warn"`: Redact + always show detailed toast (bypass rate limiter)
- `"pass"`: No redaction, log detections only (for debugging)

### Detection Engine

The `DetectionEngine` class (`src/detection/engine.ts`) is the core scanning component.

**`scan(input)` algorithm:**
1. For each pattern, create a fresh `RegExp` (resets `lastIndex` for global patterns)
2. Find all matches via `regex.exec()` loop
3. Call `pattern.redact(match)` — skip if redaction equals original (e.g., private IP addresses)
4. Resolve overlapping matches (longer match wins; if same length, higher confidence wins)
5. Apply replacements from end-to-start (preserves earlier string indices)

**Pattern structure:**
```typescript
{
  id: "openai-api-key",        // unique kebab-case ID
  name: "OpenAI API Key",      // human-readable name
  category: "api-keys",        // PatternCategory
  pattern: /sk-proj-[A-Za-z0-9_-]{20,}/g,  // regex with /g flag
  redact: () => "[REDACTED]",  // redaction function
  confidence: "high",          // low | medium | high
}
```

The `redact` function can be conditional — PII patterns (credit card, IPv4) validate the match before redacting. Credit cards use Luhn checksum; IPv4 excludes private ranges.

## How to Make Common Changes

### Adding a New Detection Pattern

1. Choose the file in `src/detection/patterns/` matching the category
2. Add a `DetectionPattern` to the exported array
3. Add tests in `tests/detection-patterns.test.ts`:
   ```typescript
   test("detects My Service API key", () => {
     const p = apiKeyPatterns.find((p) => p.id === "my-service-key")!
     testPattern(p, "key is myservice_abc123...", true)
     testPattern(p, "no key here", false)
   })
   ```
4. Run `bun test` and `bun run typecheck`

### Adding a New Pattern Category

You must update **5 files**:
1. `src/types.ts` — add to `PatternCategory` union type
2. `src/config/schema.ts` — add to `patternCategorySchema` enum
3. `src/config/defaults.ts` — add to `DEFAULT_CONFIG.categories` with `true` or `false`
4. `src/audit/session-stats.ts` — add to `detectionsByCategory` initialization in the constructor
5. `src/detection/patterns/index.ts` — import and spread new patterns into `ALL_BUILTIN_PATTERNS`

Then create a new pattern file and add tests.

### Adding a New Hook

1. Create `src/hooks/my-hook.ts` following the factory pattern (see [Hook System](#hook-system))
2. Define a `MyHookDeps` interface with only the dependencies you need
3. Import and create in `src/index.ts`
4. Register in the returned hooks object under the appropriate hook name
5. Add to session reset in the `event` handler if the hook has mutable state
6. Add tests in `tests/hooks.test.ts`

### Adding a New Custom Tool

1. Create `src/tools/my-tool.ts`:
   ```typescript
   interface MyToolDeps { /* deps from index.ts */ }

   export function createMyTool(deps: MyToolDeps) {
     return {
       description: "Tool description for the AI",
       async execute(args: { /* typed args */ }): Promise<string> {
         return "text response for AI"
       },
     }
   }
   ```
2. Import in `src/index.ts`, create with deps, register in `tool: { ... }` using `tool()` from `@opencode-ai/plugin`

### Modifying Configuration

When adding a new config field:
1. `src/types.ts` — add to `SecurityGuardConfig` (required field with concrete type)
2. `src/config/schema.ts` — add to the appropriate Zod schema (make it `.optional()`)
3. `src/config/defaults.ts` — add the default value to `DEFAULT_CONFIG`
4. `tests/config.test.ts` — test the default value and Zod validation (valid + invalid)

The `deepMerge()` in `src/config/index.ts` will automatically handle the new field without modification, as long as it follows the existing nesting structure.

## Code Conventions

### Imports

```typescript
import type { SomeType } from "../types.js"   // Type-only imports use `import type`
import { someFunction } from "../utils.js"      // Value imports use `import`
```

**All imports must use `.js` extension** — this is required by ESM with `moduleResolution: bundler`.

### Naming

| Element | Convention | Example |
|---|---|---|
| Files | kebab-case | `input-sanitizer.ts` |
| Types/Interfaces | PascalCase | `SecurityGuardConfig` |
| Functions | camelCase | `createInputSanitizer` |
| Constants | UPPER_SNAKE or camelCase | `RISK_LEVEL_ORDER`, `DEFAULT_CONFIG` |
| Pattern IDs | kebab-case | `openai-api-key` |
| Config keys | camelCase | `blockThreshold` |

### Types

- **All types live in `src/types.ts`**. Do not scatter type definitions across files.
- The only exception is local `interface XxxDeps` for hook/tool factory dependency injection — these live in the file that uses them.
- Use `import type` for type-only imports.

### Error Messages

```typescript
// Blocking errors (visible to AI)
throw new Error(`Security Guard: Access to "${filePath}" is blocked by security policy. ...`)

// Non-critical (silent catch)
try { await client.tui.showToast({ ... }) } catch { /* toast failure is non-critical */ }
```

Blocking error messages should:
- Start with `"Security Guard:"`
- Explain what was blocked and why
- Suggest an alternative when applicable (e.g., "ask the user to temporarily allowlist it")

### Toast Messages

Follow the established prefix pattern:
- Blocked: `🛡 Blocked: {reason}`
- Redacted: `🔒 Redacted {count} secret(s) in {tool} output`
- Warning: `⚠️ Warning: {explanation}`
- Detection (pass mode): `⚠️ Detected {count} secret(s) (NOT redacted)`
- Denied (permission): `🛡 Denied: {explanation}`
- Risk (permission): `⚠️ Risk detected ({level}): {explanation}`

### Debug Logging

```typescript
const debugLog = config.llm.debug
  ? (msg: string) => {
      client.app.log({
        body: { service: "security-guard", level: "info", message: msg },
      }).catch(() => {})
    }
  : undefined

debugLog?.(`Some message: ${variable}`)
```

The `debugLog` is a nullable function. When debug is disabled, it's `undefined` and `?.` makes calls no-ops.

## Testing Conventions

### Test Structure

Tests use Bun's built-in test runner. Structure:

```typescript
import { describe, test, expect } from "bun:test"

describe("Feature Name", () => {
  test("describes expected behavior", async () => {
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

### Shared Test Helpers

`tests/hooks.test.ts` defines reusable helpers:

```typescript
// Mock client — all methods resolve to undefined
const mockClient: PluginClient = {
  app: { log: async () => undefined },
  tui: { showToast: async () => undefined },
}

// Test audit config — file logging disabled
const testAuditConfig = { ...DEFAULT_CONFIG.audit, enabled: false }

// Creates all common dependencies
function createTestDeps() {
  const engine = createDetectionEngine(DEFAULT_CONFIG)
  const auditLogger = new AuditLogger(testAuditConfig)
  const sessionStats = new SessionStats("test")
  const toastState: ToastState = { lastToastTime: 0, minInterval: 0 }
  const sessionAllowlist = new Set<string>()
  const evaluatedCalls = new Set<string>()
  return { engine, auditLogger, sessionStats, toastState, sessionAllowlist, evaluatedCalls }
}
```

When testing hooks, spread `createTestDeps()` and add hook-specific deps:
```typescript
const hook = createInputSanitizer({
  ...deps,
  config: DEFAULT_CONFIG,
  client: mockClient,
  safetyEvaluator: null,
  sessionAllowlist: deps.sessionAllowlist,
})
```

### Testing Patterns

For detection pattern tests in `tests/detection-patterns.test.ts`:

```typescript
function testPattern(pattern: DetectionPattern, input: string, shouldMatch: boolean) {
  const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags)
  const match = regex.exec(input)
  if (shouldMatch) {
    expect(match).not.toBeNull()
    if (match) {
      const redacted = pattern.redact(match[0])
      expect(redacted).not.toBe(match[0])  // Redaction actually changes the text
    }
  } else {
    if (match) {
      const redacted = pattern.redact(match[0])
      expect(redacted).toBe(match[0])  // Match but no redaction = not sensitive
    }
  }
}
```

### Test File Organization

| File | What It Tests |
|---|---|
| `config.test.ts` | Default values, Zod schema accepts valid configs, rejects invalid configs |
| `hooks.test.ts` | Hook behavior with mocked dependencies (blocking, redaction, allowlist, env) |
| `detection-patterns.test.ts` | Individual pattern matching and redaction across all categories |

## Things to Watch Out For

### Regex `lastIndex` State

Global regexes (`/g` flag) maintain `lastIndex` state. The `DetectionEngine.scan()` method creates a **fresh RegExp** from `pattern.source` and `pattern.flags` for each scan. If you reuse a regex object across calls without resetting it, matches will be skipped.

### Array vs Object Merge

The `deepMerge()` function **replaces arrays entirely**. If a user config specifies `blockedFilePaths: [".env"]`, it replaces the entire default list — it does NOT append. This is intentional. Do not change this behavior.

### Session Reset

When `session.created` event fires, ALL mutable state must be reset:
```typescript
sessionStats.reset("")
sessionAllowlist.clear()
evaluatedCalls.clear()
policyInjected = false
llmSanitizer?.reset()
safetyEvaluator?.reset()
```

If you add new mutable state, add its reset to the event handler in `src/index.ts`.

### Tool Exclusion

Tools in `config.excludedTools` (default: `["glob", "list"]`) skip ALL processing — no scanning, no blocking, no safety evaluation. This check happens early in both `input-sanitizer.ts` and `output-redactor.ts`.

### Whitelist Priority

In `src/utils/paths.ts`, the whitelist is checked **before** the blocklist. If a path matches both, it is NOT blocked. This allows patterns like blocking all `.env*` files but whitelisting `.env.example`.

### Permission Deduplication

The `evaluatedCalls: Set<string>` prevents double LLM evaluation. When `permission.ask` fires and evaluates a call, it adds the `callID` to this set. When `tool.execute.before` fires for the same call, it checks the set and skips re-evaluation. This is critical for:
- Avoiding wasted LLM calls
- Preventing inconsistent results between the two hooks

### Fail-Open LLM

Both `SafetyEvaluator.evaluate()` and `LlmSanitizer.sanitize()` catch all errors and return safe defaults. Do not change this behavior — the plugin must never become a blocker when the LLM is unavailable.

### Toast Rate Limiting

The `canToast()` function enforces a 2-second minimum interval between toasts. The `ToastState` object is shared across hooks. In `"warn"` output mode, toasts bypass the rate limiter intentionally. Do not add rate limiting to warn-mode toasts.

## File Dependency Graph

Understanding which files import which helps you know what to modify together:

```
src/index.ts
├── src/config/index.ts         → loads and merges config
├── src/detection/index.ts      → creates DetectionEngine
├── src/audit/index.ts          → AuditLogger
├── src/audit/session-stats.ts  → SessionStats (re-exported from audit/index.ts)
├── src/llm/index.ts            → LlmSanitizer
├── src/llm/safety-evaluator.ts → SafetyEvaluator
├── src/hooks/input-sanitizer.ts
├── src/hooks/output-redactor.ts
├── src/hooks/permission-handler.ts
├── src/hooks/env-sanitizer.ts
├── src/hooks/compaction-context.ts
├── src/hooks/security-policy.ts
├── src/tools/security-dashboard.ts
├── src/tools/security-report.ts
├── src/tools/rules-manage.ts
└── src/types.ts                → imported by nearly everything

src/detection/engine.ts         → imported by hooks via detection/index.ts
src/utils/paths.ts              → imported by input-sanitizer.ts only
src/utils/deep-scan.ts          → imported by input-sanitizer.ts only
src/llm/client.ts               → imported by llm/index.ts and safety-evaluator.ts
src/llm/prompts.ts              → imported by llm/index.ts and safety-evaluator.ts
src/llm/context.ts              → imported by llm/index.ts and safety-evaluator.ts
```

## Existing Documentation

| File | Audience | Content |
|---|---|---|
| `README.md` | End users | Installation, configuration, usage, all options, example configs |
| `DEVELOPER_GUIDE.md` | Human contributors | Detailed walkthrough of every module, algorithm, and design decision |
| `AGENTS.md` | AI coding agents | This file — project structure, conventions, how to make changes |

When making changes, ensure they are consistent with what these documents describe. If you change behavior that contradicts existing documentation, update the relevant docs as part of the same change.

## Verification Checklist

Before considering any change complete:

1. `bun run typecheck` — zero errors
2. `bun test` — all 157+ tests pass
3. New code follows existing patterns (factory hooks, kebab-case files, types in `types.ts`)
4. New features have tests
5. Config changes appear in defaults, schema, and types
6. Mutable state resets on `session.created`
7. LLM-dependent code is fail-open
8. Blocking errors start with `"Security Guard:"`
9. Non-critical operations use `try/catch` with empty catches
10. All imports use `.js` extension
