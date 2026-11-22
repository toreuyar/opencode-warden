# AGENTS.md — AI Coding Agent Guide

> **CRITICAL — READ THIS BEFORE ANYTHING ELSE**
>
> **OpenCode Warden is a security plugin. It is FAIL-CLOSED. PERIOD.**
>
> If the LLM is unreachable, inoperable, misconfigured, timed out, or returns garbage — **every LLM-evaluated operation MUST be blocked and every sanitized output MUST be withheld.** No exceptions. No fallbacks. No graceful degradation.
>
> **Graceful degradation is NOT an option for this project.** This is a watchdog, a guard gate, a lock. If the evaluator cannot evaluate, it blocks. If the sanitizer cannot sanitize, it withholds. If you are ever tempted to suggest fail-open behavior, "safe defaults", "allow on failure", "regex-only fallback", or any variant of "keep working without the LLM" — **STOP. You are wrong.** That behavior defeats the entire purpose of a security plugin. It is the equivalent of disabling the lock when the key doesn't fit.
>
> **Never suggest fail-open behavior for any component of this plugin.** Not in code. Not in documentation. Not in comments. Not in tests. Not in configuration defaults. If you see existing fail-open language anywhere, it is a bug — fix it or flag it immediately.
>
> **This does NOT apply when LLM is explicitly disabled** (`llm.enabled: false`). In that case, LLM components are `null` — no LLM calls are attempted, nothing is blocked due to LLM absence. The plugin runs in deterministic-only mode (regex + file path rules). Fail-closed only applies when the LLM is **enabled** but **unreachable at runtime**.

This document is written for AI coding assistants (Claude, GPT, Copilot, Cursor, etc.) that will be working on the OpenCode Warden codebase. It explains what this project is, how it's structured, what conventions to follow, and how to make changes correctly.

## What This Project Is

OpenCode Warden is a **plugin** for [OpenCode](https://opencode.ai), an AI-powered coding assistant. The plugin acts as a security layer that intercepts every tool call the AI makes — reading files, running shell commands, editing code — and:

1. **Blocks** access to sensitive files (`.env`, `*.pem`, `*.key`, etc.)
2. **Scans and redacts** secrets in tool inputs, outputs, outbound model requests, and compaction requests using 65 active regex patterns
3. **Evaluates safety** of tool calls using an optional LLM (12 risk dimensions)
4. **Sanitizes** environment variables before they reach shell commands
5. **Applies a global shell backstop** to every shell creation, including user terminals
6. **Logs** all security events to an audit trail

The plugin is loaded by the OpenCode runtime and registers **V2 domain hooks** that fire at specific points in the tool/request lifecycle. It has no enforcement UI of its own. Alerts flow through the package's TUI/RPC companion (`src/rpc.ts`, `src/tui.ts`, `src/tui-notifications.ts`), which carries only fixed event kinds and bounded metadata. Notifications are UX-only, may be absent if the TUI/RPC is unavailable, and never affect enforcement.

## Tech Stack

| Component | Technology |
|---|---|
| Runtime | [Bun](https://bun.sh) |
| Language | TypeScript (strict mode) |
| Test Runner | Bun's built-in (`bun:test`) |
| Schema Validation | [Zod](https://zod.dev) |
| Plugin SDK | `@opencode/plugin` (V2) |
| Module System | ESM (`import`/`export`) |
| Build | `bun run build` (keeps `sh-ast` external so it can load its packaged WASM) |

## Commands

```bash
bun install          # Install dependencies
bun test             # Run all tests
bun run typecheck    # TypeScript type checking (tsc --noEmit)
bun run build        # Build for distribution
```

**Always run `bun run typecheck` and `bun test` after making changes.** Both must pass with zero errors.

## Project Structure

```
src/
├── index.ts                      # Plugin entry point — V2 setup(ctx) wiring
├── types.ts                      # ALL shared type definitions (single file)
├── rpc.ts                        # Public notification RPC contract (event-only)
├── tui.ts                        # TUI companion entrypoint (no enforcement)
├── tui-notifications.ts          # Server bridge between hook toasts and RPC
│
├── config/
│   ├── index.ts                  # Defaults → global → project, inline fallback, failure signal
│   ├── defaults.ts               # DEFAULT_CONFIG with every field filled in
│   └── schema.ts                 # Zod schemas for user config validation
│
├── detection/
│   ├── index.ts                  # createDetectionEngine() factory
│   ├── engine.ts                 # DetectionEngine class (scan, overlap resolution)
│   ├── redactor.ts               # Simple redaction helpers
│   └── patterns/                 # Built-in pattern families (65 active by default)
│
├── hooks/
│   ├── input-sanitizer.ts        # tool.execute.before — file/tool blocking, arg scan, safety eval
│   ├── output-redactor.ts        # tool.execute.after — regex + optional LLM output redaction
│   ├── permission-handler.ts     # permission.evaluate — deterministic + LLM permission decisions
│   ├── env-sanitizer.ts          # shell.create.before — env stripping/redaction
│   ├── shell-backstop.ts         # shell.create.before — global path backstop for all shells
│   ├── outbound-sanitizer.ts     # session.context/generate/title — policy + outbound text redaction
│   ├── compaction-context.ts     # session.compaction — policy + compaction request scanning
│   ├── prompt-sanitizer.ts       # session.prompt — opt-in prompt + attachment-metadata scanning
│   ├── session-permissions.ts    # session-scoped deny-rule translation/sync (defense in depth)
│   ├── tool-surface.ts           # blockedTools removal from request/transform surfaces
│   ├── session-context.ts        # Session state helpers + TTL sweep
│   ├── v2-adapters.ts            # V2 event → internal handler adapters + fail-closed lockdown
│   └── security-policy.ts        # Builds security policy markdown for request context
│
├── llm/
│   ├── index.ts                  # LlmSanitizer class (output sanitization via LLM)
│   ├── client.ts                 # HTTP client for OpenAI-compatible APIs
│   ├── context.ts                # ConversationContext — sliding window message history
│   ├── prompts.ts                # System prompts, templates, renderTemplate()
│   ├── safety-evaluator.ts       # SafetyEvaluator class (12-dimension risk assessment)
│   ├── shell-complexity.ts       # Optional command-only composition precheck
│   ├── payload-decode.ts         # Deterministic pre-decoding of encoded payloads
│   ├── static-findings.ts        # Credential-surface + verdict-forgery detection
│   └── command-annotations.ts    # Tool-semantics annotations for tar/dc/gdb
│
├── audit/
│   ├── index.ts                  # AuditLogger — orchestrates file + app logging
│   ├── file-logger.ts            # Buffered, rotating JSON-line file logger
│   └── session-stats.ts          # In-memory session statistics and timeline
│
├── tools/                        # 7 custom tools (help, dashboard, report, audit,
│                                 # evaluate, config, rules)
│
└── utils/
    ├── paths.ts                  # Glob matching, file-target extraction, exemptions
    ├── tool-compat.ts            # V1/V2 tool-name + argument aliases
    └── deep-scan.ts              # Recursive object scanning for secrets

scripts/
├── llm-harness.ts                # LLM evaluation test harness (standalone CLI, see LLM_HARNESS.md)
├── llm-harness-tests.json        # 237-test suite (generated from WARDEN_LLM_TESTS.md)
├── llm-harness.config.example.json # Example harness config (real config is gitignored)
├── run-full-suite.sh             # Multi-model full-suite runner
└── LLM_HARNESS.md                # Harness documentation

tests/
├── config.test.ts                # Config defaults + Zod schema validation
├── config-source.test.ts         # Inline/file precedence + fail-closed config failure
├── hooks.test.ts                 # Legacy hook behavior (input, output, env, compaction)
├── fail-closed-evaluator.test.ts # Evaluator outage/null-component regressions
├── detection-patterns.test.ts    # Pattern detection across all categories
├── payload-decode.test.ts        # Payload decoder + prompt integration
├── v2-*.test.ts                  # V2 adapters, native hooks, session policy
├── tui-notifications.test.ts     # RPC contract, bridge, TUI rendering
└── warden-fixes.test.ts          # Bypass-gate + ground-truth injection regressions
```

## Architecture at a Glance

The plugin entry point (`src/index.ts`) exports `Plugin.define({ id, setup(ctx) })`. During `setup(ctx)` Warden:

1. Loads config: defaults → global `~/.config/opencode/opencode-warden.json` → project `.opencode/opencode-warden.json`. Inline `ctx.options` is used **only** when neither file exists; if either file exists, files win entirely.
2. On a config failure, registers a deny-all/withhold-all lockdown and returns without constructing normal components. It never throws out of `setup()` (a failed setup drops every Warden hook and leaves the host unprotected).
3. Creates a `DetectionEngine`, `AuditLogger`, `SessionStats`, optional LLM providers/sanitizers/evaluators, and hook handlers that share per-session state via dependency injection.
4. Registers V2 domain hooks and custom tools through `ctx.tool.transform(editor => ...)`.
5. Warns (but does not refuse activation) when `ctx.app.version` is below the supported floor `2.0.18`, and advises that typed per-call vetoes require `2.0.29+`.

**Data flow (V2 hook order observed by the runtime probe):**

```
session.prompt (opt-in prompt + attachment metadata scan; throws to block)
    ↓
tool.execute.before (authoritative per-call gate)
    → session deny-rule lazy sync
    → blockedTools / excludedTools / sshOnlyMode gates
    → block sensitive file targets (V2 `path`, patch `patchText`, shell targets)
    → regex deep-scan args → redact in-place
    → LLM safety eval (unless deduped) → block/warn (outage always blocks)
        ↓
shell.create.before (shell only)
    → global file-path backstop for every shell (agent or user)
    → strip/redact environment variables
        ↓
permission.evaluate (when the host asserts a permission)
    → deterministic tool/path checks before LLM eligibility
    → LLM safety eval → deny/ask/allow + denial message
        ↓
[tool executes]
        ↓
tool.execute.after
    → regex + optional LLM sanitization of content/title/metadata
    → error-message/cause sanitization
    → audit log + sanitized TUI/RPC notification (UX only)
        ↓
session.context (before each primary provider dispatch)
    → append security policy system part (per request, never stored)
    → remove blocked tools from request definitions
    → redact supported outbound text + tool-result text/JSON
        ↓
session.generate (auxiliary full-context request)
    → same policy, blocked-tool removal, and outbound redaction as context
        ↓
session.title (tool-less title request)
    → deterministic outbound redaction; no policy injection
        ↓
session.compaction (before summary request)
    → same deterministic policy + outbound scan
```

Hook ordering across plugins is registration order; there is no priority API. Warden cannot guarantee its mutations are final if another plugin runs later. The host and all loaded plugins are trusted, and Warden should be loaded last where possible.

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

### Hook inventory

Warden registers these OpenCode V2 hooks (see `src/index.ts`; domain-specific mapping lives in `src/hooks/v2-adapters.ts`):

| V2 Hook | Source | Purpose |
|---|---|---|
| `session.prompt` | `prompt-sanitizer.ts` | Opt-in (`scanUserPrompts: true`) scan of user/subtask prompt text plus attachment **metadata** (file URI/name/description, agent/skill names, mention text). Throws to abort prompt admission. File contents are never read. |
| `session.context` | `index.ts` + `outbound-sanitizer.ts` + `tool-surface.ts` | Per primary model request: append the security policy as a system part, remove blocked tools from request definitions, and redact supported outbound text/tool-result text. Historical tool-call input strings are structurally redacted in the request projection (ids/names/keys/shape preserved); file/media identifiers are scanned read-only and detection withholds; provider-signed/encrypted text or unsupported input shapes abort rather than being rewritten. Never writes stored history. |
| `session.generate` | `index.ts` + `outbound-sanitizer.ts` + `tool-surface.ts` | Auxiliary full-context request: same policy append, blocked-tool removal, and deterministic outbound scan as `session.context`. Unsupported shapes/scan failures abort preparation. |
| `session.title` | `index.ts` + `outbound-sanitizer.ts` | Tool-less title request: deterministic outbound redaction of system/messages. Policy is deliberately **not** appended so title output is preserved. Unsupported shapes/scan failures abort preparation. |
| `tool.execute.before` | `input-sanitizer.ts` | Authoritative per-call gate: `blockedTools`, file path blocking, patch `patchText` targets, regex deep-scan + redaction, LLM safety evaluation. Throws a per-call veto: typed `Tool.Error` on 2.0.29+, untyped rejection on 2.0.18–2.0.28. |
| `shell.create.before` | `shell-backstop.ts` + `env-sanitizer.ts` | Global path backstop for **every** shell (including user terminals), then env stripping/redaction. Deterministic only. |
| `permission.evaluate` | `permission-handler.ts` via `v2-adapters.ts` | Deterministic tool/path/resource checks, then optional LLM evaluation. Writes `effect` (`deny`/`ask`/`allow`) and `message` back onto the evaluation. |
| `tool.execute.after` | `output-redactor.ts` via `v2-adapters.ts` | Regex + optional LLM redaction of textual content, structured-output fallback, metadata, and error message/cause. Withholds output on sanitizer failure. |
| `session.compaction` | `compaction-context.ts` + `outbound-sanitizer.ts` | Scan the native compaction request (`system`/`messages`/`tools`) and append the policy. Unsupported shapes/scan failures abort preparation. |
| `tool.transform` | `index.ts` + `tool-surface.ts` | Add the 7 Warden tools, then remove configured `blockedTools` by effective id (including a just-added custom tool). |
| event subscription | `index.ts` | `session.created` / `session.deleted` / `session.permissions` lifecycle and deny-rule cache invalidation. |

`session.prompt` is unusual in that **throwing aborts prompt admission** — OpenCode persists the message and parts only after the hook returns, so a blocked prompt never reaches the model. The TUI surfaces a generic `"Session error"` toast regardless of the detailed reason; the reason is in the audit/diagnostic log. That UX limitation is why prompt scanning ships opt-in.

**Failure channels:** only `tool.execute.before` has a typed `Tool.Error` veto, and only on host 2.0.29+. `session.*` and `shell.create.*` hooks have no typed failure channel; throws abort request preparation/spawn as a defect. This is still fail-closed (the operation does not proceed), but not a clean user-facing veto. Runtime behavior below 2.0.18 is unsupported: below-floor runtimes warn and keep protections, but host compatibility is not guaranteed. On supported hosts 2.0.18–2.0.28, `execute.before` still aborts the blocked call, but through the older untyped per-call rejection path exercised on 2.0.18; typed veto behavior is only guaranteed on 2.0.29+.

### Session Lifecycle

Warden maintains per-session state in a `Map<sessionID, SessionSecurityState>` (`src/index.ts`). New entries are created lazily via `getSessionState()` and reset via `resetSessionState()` on `session.created`. Cleanup happens three ways:

1. **`session.deleted` event** — removes the state entry and drops the session deny-rule sync cache immediately
2. **TTL sweep** — `setInterval` (hourly) calls `sweepStaleSessions()` (`src/hooks/session-context.ts`) to drop entries whose `lastAccessed` is older than 24 hours; it also drops the session deny-rule cache. The timer is `unref`'d so it can't keep the process alive
3. **`session.permissions` event** — invalidates the deny-rule cache so the next lazy sync re-reads host changes and re-appends Warden rules

`SessionSecurityState` carries: `sessionStats`, `toastState`, `sessionAllowlist`, `evaluatedCalls`, `writtenFileRegistry`, `llmSanitizer`, `safetyEvaluator`, and `lastAccessed`. Security policy is no longer session state: it is appended fresh to each request's `system` array by `session.context` and `session.generate` (and to compaction requests); `session.title` opts out.

### Shared Mutable State

These objects are shared by reference across multiple hooks and reset on `session.created`:

| Object | Type | Shared Between | Purpose |
|---|---|---|---|
| `toastState` | `ToastState` | input-sanitizer, output-redactor, env-sanitizer, prompt-sanitizer | Rate-limit notification attempts (2s window) |
| `sessionAllowlist` | `Set<string>` | input-sanitizer, permission-handler | Temporary exact-path access overrides |
| `evaluatedCalls` | `Set<string>` | permission-handler, input-sanitizer | Dedup between `permission.evaluate` and `tool.execute.before`, keyed by the shared tool call id |

Hooks can interleave at `await`; single-threaded JavaScript does not protect
shared session state. Session permission sync uses an in-flight promise cache,
keyed per session and race-safe on `forget()`. LLM conversation exchanges bind
their prompt and completion through `ConversationContext.beginExchange()`; do
not use the legacy single pending message slot in concurrent production paths.

Provider requests use the process-wide FIFO in `src/llm/request-queue.ts`.
Capacity is keyed by normalized completion URL, not session/model/name.
`requestPolicy.concurrency: 1` serializes every chain sharing that endpoint.
Limits are opt-in; the strictest positive cap among live registrations wins.
Stable per-project/component ownership replaces limits on reload, with tokens
protecting the new registration from stale disposal/update. Queue admission
precedes the HTTP timeout. Slots release in `finally`;
retry backoff happens outside them. `maxAttempts` includes the first attempt
and overrides legacy sanitizer retryCount. Overload and exhausted attempts
remain fail-closed; admission never approves or deduplicates an evaluation.

`request-context.ts` uses async-local evaluation scopes. The total deadline
spans prechecks, evaluation, retries/fallback and queue wait; nested scopes can
shorten but never extend it. Cancellation removes waiters and interrupts
backoff/HTTP without retry. V2 Promise hooks do not expose a tool AbortSignal:
use lifecycle cancellation on idle/deletion/reset/disposal, and the real
execution signal for the custom evaluation tool. Do not claim exact per-tool
cancellation for hooks. Interrupted inference pauses the endpoint before
releasing capacity; Retry-After also pauses it. Per-attempt chat logger forks
isolate counters and tag all fragments. Scheduling telemetry contains only
generated IDs and bounded operational metadata, never prompt content.

### Session-Scoped Deny Rules (Defense in Depth)

`src/hooks/session-permissions.ts` translates only policy that OpenCode can express **exactly**:

- `blockedTools` literal names → deny rules for every accepted alias spelling (`shell`/`bash`, `subagent`/`task`). Wildcard entries are omitted because Warden's comparison is literal while permission wildcards broaden.
- Literal **absolute** `blockedFilePaths` → deny rules for `read`/`glob`/`grep` and `write`/`edit`/`patch`.
- Literal **absolute** `writeProtectedPaths` → deny rules for writes only.
- Whitelisted paths are never emitted. Configured glob/relative/`~`/`host:` entries and shell path policy are omitted (OpenCode permission resources are exact strings; shell resources are raw commands). For a literal absolute path **inside** the project directory, Warden emits both the absolute path and the host's project-relative resource; paths outside the project emit only the absolute resource.

`session.update({ permissions })` **replaces** the host ruleset, so Warden re-reads, merges, and re-reads immediately before writing. If the host ruleset changed in between, the update is deferred (there is no compare-and-set, so this narrows but does not eliminate the race). Read/update failures are logged and ignored. These rules are a second layer only: `tool.execute.before`, `permission.evaluate`, the shell backstop, and output redaction remain authoritative, and a failed sync never changes an allow/deny decision.

### Configuration Hierarchy

```
Built-in defaults (src/config/defaults.ts)
    ↓ deep merge
Global config (~/.config/opencode/opencode-warden.json)
    ↓ deep merge
Project config (.opencode/opencode-warden.json)
    ↓ only if neither file exists
Inline plugin options (ctx.options)
```

The `deepMerge()` function in `src/config/index.ts`:
- Objects merge recursively (key by key)
- Arrays are **replaced entirely** (not concatenated)
- `undefined` values in source are skipped
- Primitives overwrite

This means user config files only need to specify overrides. The Zod schema makes every field optional.

**Inline fallback rule:** `ctx.options` is validated only when neither the global nor the project config path exists. If either path exists — even if it is invalid, unreadable, a dangling symlink, or a directory — inline options are ignored entirely and the file source wins. There is no fallback to defaults or a lower layer for an invalid present source.

**Invalid configuration is active lockdown, not unload:** `loadConfig()` returns `{ config, warnings, failure }`. A non-null `failure` makes `src/index.ts` register deny-all/withhold-all hooks and return without constructing normal components. `setup()` never throws for a loader/config failure, because a failed setup deactivates the plugin and leaves OpenCode unprotected. The returned fail-closed shell config is defense in depth only.

**Do not log configured values** from `ctx.options`, the resolved config, or JSON parser errors. Failure diagnostics must use only the sanitized `source`, `path`, `code`, and issue paths/messages.

### Runtime Compatibility

The supported host floor is **OpenCode 2.0.18**. `package.json` declares the peer range `@opencode/plugin: ^2.0.18` because that published SDK exposes every V2 surface Warden uses: `Plugin.define/setup`, `ctx.app`/`location`/`options`, the tool/session/permission/shell/event domains, and the `Tool.Result`/`Tool.Error` types. The API check compared the published 2.0.18 package with the installed 2.1.4 SDK: `plugin.d.ts`, `tool.d.ts`, `shell.d.ts`, `event.d.ts`, and `app.d.ts` expose the same surface Warden calls; the diffs are later additions Warden does not use (`permission.assert`, `session.compact`/`remove`, `credential.activate`). Development and `bun run typecheck` intentionally stay on the installed 2.1.4 SDK; the peer range represents the consumer API floor, not the development toolchain. The peer range does not claim typed-veto behavior: `@opencode/plugin` 2.0.29 added the `execute.before` rejection → `Tool.Error` mapping (verified by diffing the published 2.0.18 and 2.0.29 `dist/promise/adapter.js`). On 2.0.18–2.0.28 the host aborts the blocked call through the older untyped per-call rejection path exercised by the 2.0.18 bounded runtime validation.

Warden warns (once, via console, the app log, and the diagnostic log) when `ctx.app.version` is coherently below 2.0.18, and separately advises when a supported 2.0.18–2.0.28 host lacks the typed `Tool.Error` veto mapping. It **never refuses activation**. A failed setup drops every hook and the host continues unprotected. Unparseable versions produce no warning. Protections remain installed on below-floor runtimes; host compatibility there is not guaranteed.

**Verification status:** bounded runtime validation was performed on OpenCode 2.0.18 with the built plugin loaded through a root `index.js` and local mocks. It passed the tested security behaviors, including `session.update({ permissions })` preservation/application, server RPC/SSE notification delivery, compaction policy/redaction, the untyped per-call block path, a bounded secret-write replay with structural tool-call-input projection redaction (exit 0, next request redacted, policy present), and a title/generate replay (tool-less title sent `[REDACTED]` with no policy and persisted `Replay Title`; generate sent redacted text with policy/tools and returned `PROBE_DONE`). The typed veto mapping introduced in 2.0.29 and the 2.1.4 hook shapes are source/package-verified, not runtime-probed on a 2.0.29 or 2.1.4 binary. Live rendered TUI toasts remain untested; no external provider or 2.0.29/2.1.4 binary was used. Structured output passed through the host-normalized content path; the content-less fallback branch is unit-test only. Raw pre-hook tool-call input remains at rest; request projection is not at-rest scrubbing. Do not upgrade these bounded 2.0.18 results into a full certification of 2.0.18, 2.0.29, or 2.1.4.

### Error Handling Philosophy

**Two categories:**

1. **Critical (can throw)**: File path blocking, safety evaluation blocking, and LLM evaluation failures. These throw `Error` (or return a block recommendation) to prevent tool execution. The error message is visible to the AI.

2. **Non-critical (catch and continue)**: Toast notifications and audit logging. These use `try/catch` with empty catches.

**LLM components are fail-closed**: If the LLM is unavailable, misconfigured, times out, or returns garbage while `llm.enabled` is true, the safety evaluator marks the result `evaluationFailed` and the caller blocks/denies **regardless of `actionMode`** (including `warn` and `permission`). The output sanitizer withholds output. A genuine model risk verdict may still follow `warn`, but an evaluator outage may not. If an enabled component is missing (`safetyEvaluator`/`outputSanitizer` is `null` for a tool that is in its configured list), the operation also blocks. The only exception is explicit `llm.enabled: false` (or an explicitly disabled component): then components are absent by design, no LLM calls are attempted, and deterministic-only mode runs without outage blocking.

Pattern you will see frequently:
```typescript
try {
  await client.tui.showToast({ ... })
} catch { /* toast failure is non-critical */ }
```

This is intentional. Do not add error logging to these catches. The V2 entrypoint routes `showToast` through `src/tui-notifications.ts`, which emits a strictly sanitized RPC event; registration/delivery failure is reported at most as a fixed diagnostic and never affects enforcement. Audit/diagnostic logging is the durable signal. Do not add explicit `notify()` calls at paths that already call `showToast`; that would duplicate alerts.

### Action Modes

Two configurable action modes control behavior:

**Input safety (`llm.safetyEvaluator.actionMode`):**
- `"block"` (default): Throw Error to block dangerous calls
- `"permission"`: Use OpenCode's permission system — deny on block, ask on warn, allow on allow. If the permission hook does not fire, `tool.execute.before` falls back to `"block"` semantics
- `"warn"`: Show a warning and allow a genuine risky call to proceed — **but evaluator failure still throws**

**Output sanitization (`llm.outputSanitizer.actionMode`):**
- `"redact"` (default): Auto-redact secrets in output
- `"warn"`: Redact + always show detailed notification (bypass rate limiter)
- `"pass"`: No redaction, log detections only (for debugging)

`"pass"` is an explicit detection-only debugging mode: it deliberately skips LLM sanitization and withholding for that output, so do not treat it as a secure default. For every other mode, an enabled-but-missing sanitizer or unavailable provider chain withholds output rather than releasing unsanitized content.

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
3. Import and create it in `src/index.ts`
4. Register it with the appropriate V2 domain in `setup(ctx)` (for example `await ctx.tool.hook("execute.before", ...)` or `await ctx.session.hook("context", ...)`). There is no returned hook object in V2.
5. Add to session reset/cleanup if the hook has mutable state
6. Add tests. Use `tests/v2-*.test.ts` for V2 event shapes and `tests/hooks.test.ts` for the internal V1-shaped handlers.

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
2. Import it in `src/index.ts`, create it with deps, and register it inside `ctx.tool.transform((editor) => { editor.add({ name, description, input, execute }) })`. Do not use the V1 `tool()` map. Keep `blockedTools` removal at the end of the transform so a newly added tool is also filtered.

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

- **Shared types live in `src/types.ts`**. Prefer adding shared/config/audit types there.
- **Allowed local exceptions:** local `interface XxxDeps` for factory dependency injection; V2 event-shape structural types and `PermissionInput`/`PermissionDecision` in `src/hooks/v2-adapters.ts` / `permission-handler.ts` (they match host interfaces without importing host internals). Final cleanup may relocate these, but do not duplicate shared config/audit types.
- Use `import type` for type-only imports.

### Error Messages

```typescript
// Blocking errors (visible to AI)
throw new Error(`Security Guard: Access to "${filePath}" is blocked by security policy. ...`)

// Non-critical (silent catch)
try { await client.tui.showToast({ ... }) } catch { /* notification failure is non-critical */ }
```

Blocking error messages should:
- Start with `"Security Guard:"` or `"Warden:"`
- Explain what was blocked and why
- Suggest an alternative when applicable (e.g., "ask the user to temporarily allowlist it")

### Notification Copy

The internal hooks follow the established prefix pattern; the notification bridge classifies these into closed event kinds and discards the raw text:
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
    const output = { args: { path: "/project/test.ts" } }
    await hook(input, output)

    // Assert
    expect(output.args.path).toBe("/project/test.ts")
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
  session: { prompt: async () => undefined },
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
  const writtenFileRegistry = new Map<string, WrittenFileMetadata>()
  return {
    engine, auditLogger, sessionStats, toastState, sessionAllowlist,
    evaluatedCalls, writtenFileRegistry, diagnosticLogger: null,
    outputTriage: null, outputTextTriage: null,
  }
}
```

When testing internal hooks, spread `createTestDeps()` and add hook-specific deps:
```typescript
const hook = createInputSanitizer({
  ...deps,
  config: DEFAULT_CONFIG,
  client: mockClient,
  safetyEvaluator: null,
  sessionAllowlist: deps.sessionAllowlist,
})
```
The production index supplies `getSessionState`; the test path supplies the individual shared objects. V2 adapter/event tests live in `tests/v2-*.test.ts` and use V2-shaped events.

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

When `session.created` fires, `resetSessionState(sessionID)` replaces ONLY that session's entry in the `sessions` map with a fresh `createSessionState()` (all defaults). Other sessions are unaffected. This is critical for multi-session correctness — see `src/index.ts`.

If you add new mutable state to `SessionSecurityState`, add it to `createSessionState()` so it gets a sensible default on session creation.

### Tool Exclusion vs Blocked Tools

- `config.excludedTools` (default: `[]`) means "skip Warden's per-tool input/output processing" for that tool — no input scanning, file blocking, output redaction, or safety evaluation. It does **not** hide the tool and is unrelated to `blockedTools`. Global outbound scanning (`session.context`, `session.generate`, `session.title`, `session.compaction`) still applies to all messages, including results and historical inputs from excluded tools. The check runs early in `input-sanitizer.ts` and `output-redactor.ts` only.
- `config.blockedTools` blocks the tool entirely. It is enforced in three places: the input sanitizer (throws), the permission handler (deterministic deny), and the tool surface (`session.context`/`session.generate` remove it per request; `tool.transform` removes it from the registered list). Both are alias-aware, so configured `shell` also matches runtime `bash` and vice versa; `subagent` matches `task`.

### Whitelist Priority

In `src/utils/paths.ts`, the whitelist is checked **before** the blocklist. If a path matches both, it is NOT blocked. `whitelistedPaths` entries are **exact paths** (absolute, `~`-prefixed, or cwd-relative), never globs; the blocklist is the glob-aware layer. This allows blocking all `.env*` files while whitelisting the exact `.env.example` path.

### Read vs Write Access Modes

File protection has two tiers (see `isPathBlockedForMode` in `src/utils/paths.ts`):

- **`blockedFilePaths`** — blocks BOTH read and write (secrets, keys, credentials). Checked for every access.
- **`writeProtectedPaths`** — blocks WRITE only; reads are allowed (logs, state files). Checked only for write operations.
- **`redactionExemptPaths`** — does NOT block access. Skips secret redaction on matching paths across all tools: `write`/`edit`/`patch` inputs (including every patch target), `read` outputs, shell redirections (`>`, `>>`, `tee`, `truncate`), shell reads (`cat`/`head`/`tail`), outbound `session.context`/`session.generate`/`session.title` tool results attributable to a read, and SSH/SCP/rsync/rclone operations (see `isRedactionExempt` in `src/utils/paths.ts`). Use case: source files that legitimately contain API keys. File blocking, write-protection, and LLM safety evaluation still apply. Supports `host:` prefix for remote-only exemption (e.g. `host:web-*:/etc/myapp/**`).

### Secret Redaction Switches

Three nested knobs control in-place redaction (see `input-sanitizer.ts` Step 2, `output-redactor.ts` Pass 1+2, `outbound-sanitizer.ts`):

- **`redactionEnabled`** (default `true`) — master kill switch. When `false`, deepScan is skipped on every tool's args, output regex+LLM redaction is skipped for every tool, and outbound scanning (`session.context`, `session.generate`, `session.title`, `session.compaction`) is skipped (the policy system part is still appended where applicable). File blocking, write-protection, env stripping, LLM safety eval, and audit logging remain on. Overrides the two knobs below.
- **`redactOnWrite`** (default `true`) — when `false`, deepScan is skipped for write/edit/patch tool inputs only. Other tools (shell, read, etc.) still redact.
- **`redactionExemptPaths`** (default `[]`) — per-path override. When a write/edit/patch target or read source matches a glob, redaction is skipped for that call only.

When multiple apply, the broadest wins (`redactionEnabled=false` overrides everything). Each skipped call is logged to the audit trail with a distinct reason: `"Redaction disabled (redactionEnabled=false)"`, `"Redaction disabled (redactOnWrite=false)"`, or `"Redaction exempt (path matches redactionExemptPaths): <path>"`.

### Redaction Policy Injection

The active values of `redactionEnabled`, `redactOnWrite`, and `redactionExemptPaths` are inlined into the LLM's security policy context (see `buildSecurityPolicyContext` in `src/hooks/security-policy.ts`). This is deliberate: the Warden config file itself is in `blockedFilePaths` by default (`**/opencode-warden.json`), so the agent cannot read the config. Inlining the values the agent needs to act on (instead of letting it discover them) preserves the security boundary while keeping the agent informed.

Policy injection is **per request**, not a synthetic message and not durable history: `session.context` and `session.generate` append the policy to the request-local `event.system` array on every invocation; `session.compaction` does the same for summary requests. `session.title` deliberately opts out because it is a narrow tool-less naming task where extra instructions can change the title. There is deliberately no text-marker deduplication (any marker can be forged by conversation content). Synthetic messages remain only for permission-denial text. Do not reintroduce `policyInjected` session state.

An access is classified as read or write by the hook based on the tool and operation:
- **Write**: `write`/`edit`/`patch` tools (patch add/delete/update/move targets); shell output-redirects (`>`, `>>`, `&>`), `tee`, `truncate`, `dd of=`; SCP/rsync/rclone **upload** (remote destination).
- **Read**: `read`/`glob`/`grep` tools; shell `cat`/`less`/`head`, input-redirect `<`; SCP/rsync/rclone **download** (remote source); SSH inner-command file references.

Shell write/read targets are extracted by `extractFileTargets()` (returns an array of `{ path, mode }`, built on `extractBashFileTargets()`). This is what enforces the blocklist against shell redirections — without it, `echo >> authorized_keys` would bypass the file blocker. V2 args use `path`; legacy `filePath` is still accepted. `patch` uses `patchText` and recognizes `*** Add File:`, `*** Delete File:`, `*** Update File:`, and `*** Move to:` targets. `*** Move to:` is a write target, and the update source is checked as well.

### Permission Deduplication

The `evaluatedCalls: Set<string>` prevents double LLM evaluation. `v2-adapters.ts` forwards `event.source.id` as the tool call id; in the 2.x SDK this is the same id emitted by `tool.execute.before` and `tool.execute.after` (source-verified, and runtime-observed on 2.0.18). When `permission.evaluate` evaluates a call, it records that id. `tool.execute.before` checks the set and skips re-evaluation. Denied/failed evaluations are not recorded, so a later attempt can re-evaluate. This avoids wasted LLM calls and inconsistent results; it is not a security boundary. In the observed host order, `execute.before` can run before `permission.evaluate`, causing duplicate evaluation but no bypass — the input sanitizer remains the authoritative pre-execution gate.

### Shell composition gates (2.1.0)

`src/utils/shell-sequence.ts` rejects adjacent top-level simple commands or
pipelines separated by `;` or command-ending newlines using `sh-ast`. It runs
before model requests in input/permission hooks and evaluator dry runs, even
with the LLM disabled, subject to existing exclusions and SSH-only scope in the
hooks. It distinguishes quoted/comment/heredoc data and does not traverse nested
constructs. Keep `sh-ast` external in the build so its packaged WASM loads.

`llm.safetyEvaluator.complexityPrecheck.enabled` defaults to `false`. When
enabled with the LLM and evaluator, `src/llm/shell-complexity.ts` sends selected
shell syntax through a stateless command-only request using the safety provider
chain. `simplify` requires a recognized structural reason and vetoes the attempt;
`continue` requires full safety evaluation, never approval or bypass. Invalid or
unavailable results block even in warn mode. Its prompt is fixed. Neither gate
extends to user terminals; their global shell backstop remains separate.

### Fail-Closed LLM

`SafetyEvaluator.evaluate()`, `evaluateFileExecution()`, and `LlmSanitizer.sanitize()` catch errors and fail closed. The evaluator distinguishes an actual model verdict from an evaluator failure with `evaluationFailed: true`; callers block/deny on that flag regardless of `warn`/`permission` mode. A genuine model `block`/`warn` recommendation is a floor and cannot be downgraded by a contradictory lower `riskLevel`. Do not change this behavior — the plugin must block when the LLM is unavailable or returns garbage. An explicitly disabled LLM (`llm.enabled: false`) is different: no LLM calls are attempted and deterministic-only mode runs without outage blocking.

Do **not** move safety evaluation onto `ctx.generate.text` or another host-routed model. The independent provider chain is deliberate: host routing changes or outages must not become a bypass. Likewise, `ctx.storage`, tool namespacing, and tool progress/cancel remain intentionally unused; see the "V2 Capabilities Intentionally Not Used" table in `DEVELOPER_GUIDE.md`.

### Notification Rate Limiting

The `canToast()` function enforces a 2-second minimum interval between notification attempts per session. The `ToastState` object is shared across hooks. In `"warn"` output mode, notifications bypass the rate limiter intentionally. Do not add rate limiting to warn-mode notifications.

In V2 the server entrypoint wires `client.tui.showToast` to `src/tui-notifications.ts`, which emits a strict event-only RPC contract (`opencode-warden.notifications`). The TUI companion (`src/tui.ts`) subscribes and renders fixed copy; it makes no allow/deny/evaluate calls. Events carry only a closed `kind`, an optional canonical tool id, and an optional bounded count — never paths, arguments, output, explanations, or raw audit text. Registration/delivery failure is non-blocking and never changes enforcement. A slow/absent TUI cannot delay hook installation or a security decision. Server RPC/SSE delivery passed on 2.0.18; live rendered TUI behavior has not been runtime-probed.

## File Dependency Graph

Understanding which files import which helps you know what to modify together:

```
src/index.ts
├── src/config/index.ts             → loads/merges config + failure signal
├── src/detection/index.ts          → creates DetectionEngine
├── src/audit/index.ts              → AuditLogger / DiagnosticLogger / LlmChatLogger
├── src/audit/session-stats.ts      → SessionStats (re-exported from audit/index.ts)
├── src/llm/index.ts                → LlmSanitizer + triage classes
├── src/llm/safety-evaluator.ts     → SafetyEvaluator
├── src/hooks/input-sanitizer.ts
├── src/hooks/output-redactor.ts
├── src/hooks/permission-handler.ts
├── src/hooks/env-sanitizer.ts
├── src/hooks/shell-backstop.ts
├── src/hooks/outbound-sanitizer.ts
├── src/hooks/compaction-context.ts
├── src/hooks/prompt-sanitizer.ts
├── src/hooks/session-permissions.ts
├── src/hooks/tool-surface.ts
├── src/hooks/session-context.ts      → sweepStaleSessions only (no prompt capture)
├── src/hooks/v2-adapters.ts
├── src/hooks/security-policy.ts
├── src/tools/security-*.ts
└── src/types.ts                      → imported by nearly everything

src/detection/engine.ts         → imported by hooks via detection/index.ts
src/utils/paths.ts              → imported by input/permission/output/outbound/shell hooks
src/utils/tool-compat.ts        → imported by hooks + config normalization
src/utils/deep-scan.ts          → imported by input-sanitizer.ts
src/llm/client.ts               → imported by llm/index.ts and safety-evaluator.ts
src/llm/prompts.ts              → imported by llm/index.ts and safety-evaluator.ts
src/llm/context.ts              → imported by llm/index.ts and safety-evaluator.ts
src/rpc.ts                      → notification contract; imported by tui bridge/companion
src/tui-notifications.ts        → server bridge; imported by index.ts
src/tui.ts                      → TUI companion entrypoint
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
2. `bun test` — all tests pass
3. New code follows existing patterns (factory hooks, kebab-case files, shared types in `types.ts`)
4. New features have tests; V2 event behavior goes in `tests/v2-*.test.ts`
5. Config changes appear in defaults, schema, and types (and example/docs)
6. Mutable state resets on `session.created`; any new per-session sync cache is forgotten on delete/TTL
7. LLM-dependent code is fail-closed when LLM is enabled, including `warn`/`permission` modes; explicit `llm.enabled: false` remains deterministic-only
8. Config failures install the active lockdown and never throw out of `setup()`
9. Tool/path policy remains alias-aware (`shell`/`bash`, `subagent`/`task`) and covers V2 `path`/`patchText` targets
10. Blocking errors start with `"Security Guard:"` or `"Warden:"`, explain the block, and suggest an alternative when applicable
11. Non-critical operations (notifications, audit) use `try/catch` with empty catches
12. All imports use `.js` extension
