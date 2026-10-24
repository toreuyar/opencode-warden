# Configuration

[← Back to README](../README.md)

## Configuration Hierarchy

Warden loads configuration from three layers, each deep-merging into the previous:

| Priority | Location | Scope |
|---|---|---|
| 1 (lowest) | Built-in defaults | Always applied |
| 2 | `~/.config/opencode/opencode-warden.json` | Global — applies to all projects |
| 3 (highest) | `.opencode/opencode-warden.json` | Project-specific — overrides global |
| Fallback only | Inline plugin `options` (`ctx.options`) | Used **only** when neither file path exists |

**Deep merge** means you only need to specify the fields you want to override. Unspecified fields inherit from the layer below. Arrays are replaced entirely, not appended.

**Inline options are a fallback, not another layer.** If the global or project file exists — even if it is invalid, unreadable, a dangling symlink, or a directory — inline `ctx.options` are ignored entirely. The file always wins; there is no fallback to defaults or a lower file layer when a present source is invalid.

**Invalid configuration is an active lockdown, not an unload.** Warden does not throw out of plugin setup (a failed setup drops every Warden hook and leaves the host unprotected). Instead it installs deny-all/withhold-all hooks: permission requests are denied, tool execution is vetoed, output/error details are withheld, and prompts, model requests, compaction, and shell creation are blocked until the configuration is fixed and OpenCode is restarted. Failure diagnostics are sanitized and never include configured values.

**Global config** is ideal for settings that apply everywhere — your LLM endpoint, personal PII preferences, custom company patterns.

**Project config** is ideal for project-specific overrides — additional blocked paths, allowlisted files, project-specific tools to monitor.

### Runtime compatibility

Warden's plugin version is independent of the OpenCode host version. This
documentation describes Warden **2.0.0**, which targets the V2 plugin API on the
OpenCode **2.x** line.

| OpenCode host | Warden plugin | Notes |
|---|---|---|
| OpenCode 1.x (V1 plugin API) | **1.3.0**, pinned | Warden 1.3.0 is the last release for OpenCode 1.x (`@opencode-ai/plugin` `^1.2.0`). Install `opencode-warden@1.3.0`; do not install 2.0.0. |
| OpenCode 2.0.0–2.0.17 | **2.0.0** | Below the declared supported floor; not verified. Loads with a warning and keeps protections installed. |
| OpenCode 2.0.18–2.0.28 | **2.0.0** | Declared supported floor, bounded runtime-validated on 2.0.18 with local mocks and a root `index.js` load. Blocks through the older untyped per-call rejection path; typed `Tool.Error` vetoes require 2.0.29+. |
| OpenCode 2.0.29+ | **2.0.0** | Supported. The typed veto mapping introduced in 2.0.29 is source/package-verified; not runtime-probed on a 2.0.29 or 2.1.4 binary. |

The supported 2.x floor is **OpenCode 2.0.18** (`@opencode/plugin` peer
`^2.0.18`; development and type-checking use the 2.1.4 SDK).
Hosts below it are expected to load Warden and keep all protections installed,
and Warden emits a warning. Hosts on 2.0.18–2.0.28 also warn that typed per-call
tool vetoes require 2.0.29+; blocking uses the older untyped per-call rejection
path. Warden never refuses activation for a version mismatch: a
failed setup would leave OpenCode entirely unprotected. This is a minimum-floor
statement, not a claim that all OpenCode 2.x versions are certified.

For OpenCode 1.x, use the `v1.3.0` README and example configuration:

```json
{
  "plugin": ["opencode-warden@1.3.0"]
}
```

> **Verification note:** bounded runtime validation on **OpenCode 2.0.18** (built
> Warden 2.0.0, root `index.js` load form, local mocks) passed config
> precedence/inline fallback, invalid-config lockdown, V2 path/shell/subagent
> blocking, write/read/error redaction, outbound tool-result redaction and policy
> injection, shell backstop, evaluator/sanitizer outage blocking in `warn`,
> `llm.enabled: false` deterministic mode, `session.update({ permissions })`
> preservation/application, server RPC/SSE delivery, and compaction policy plus
> redaction with a valid summary. This is bounded validation, not a
> certification of every host behavior. The run exercised the untyped per-call
> rejection path used on 2.0.18–2.0.28. The typed `Tool.Error` veto mapping
> introduced in `@opencode/plugin` 2.0.29 is source/package-verified, not
> runtime-probed on a 2.0.29 or 2.1.4 binary. Live rendered TUI toasts remain
> untested. A bounded 2.0.18 secret-write replay passed with structural
> tool-call-input projection redaction (exit 0, next request redacted, policy
> present); the raw pre-hook input remains at rest and this is not a broad
> certification. A bounded 2.0.18 title/generate replay also passed: title
> (tool-less) sent `[REDACTED]` with no policy and persisted `Replay Title`;
> generate sent redacted text with policy and normal tools and returned
> `PROBE_DONE`. No external provider, 2.0.29/2.1.4 binary, or live rendered TUI
> was used. Structured output passed at runtime through the normalized content
> path; the content-less fallback branch is unit-test only.

### Native V2 tool vocabulary

Policies are written in V2 names, with legacy aliases accepted in both config and runtime:

| V2 canonical | Legacy alias | Notes |
|---|---|---|
| `shell` | `bash` | Policy lists, bypass checks, and `sshOnlyMode` are alias-aware |
| `subagent` | `task` | Block/exclude either spelling to match the other |
| `path` argument | `filePath` | V2 `path` wins when both are present |
| `patchText` | — | `patch` add/delete/update/move targets are all inspected |

## Full Configuration Reference

### Root Options

| Option | Type | Default | Description |
|---|---|---|---|
| `categories` | `Record<PatternCategory, boolean>` | All `true` except `pii-ip-address` | Enable or disable detection categories |
| `disabledPatterns` | `string[]` | `[]` | Pattern IDs to disable (e.g., `["generic-bearer-token"]`) |
| `customPatterns` | `CustomPatternConfig[]` | `[]` | User-defined detection patterns |
| `whitelistedPaths` | `string[]` | `[]` | Exact file paths (absolute, `~`-prefixed, or project-relative) that bypass file blocking. Not globs — use `blockedFilePaths` for glob patterns. |
| `blockedFilePaths` | `string[]` | See [example config](#complete-example-configuration) | Glob patterns of files to block **both read and write** (secrets, keys, credentials) |
| `writeProtectedPaths` | `string[]` | `["**/var/log/**"]` | Glob patterns of files that may be **read but not written** (logs, state files). Closes the anti-forensics hole (log truncation) deterministically. Write attempts via `write`/`edit` tools and shell redirections (`>`, `>>`, `tee`, `truncate`, `dd of=`) are blocked. |
| `excludedTools` | `string[]` | `[]` | Tools to skip Warden's per-tool input/output processing (no input scanning, file blocking, output redaction, or safety evaluation). This does **not** hide the tool; use `blockedTools` for that. Global outbound scanning (`session.context`, `session.generate`, `session.title`, `session.compaction`) still applies to all messages, including results and historical inputs from excluded tools. V2 has no obsolete `list` tool. |
| `blockedTools` | `string[]` | `[]` | Tools to block entirely. Enforced by the input sanitizer, permission handler, and tool surface (per-request and transform). Alias-aware: `shell`↔`bash`, `subagent`↔`task`. |
| `sshOnlyMode` | `boolean` | `false` | Only monitor remote commands (ssh, scp, sftp, rsync, rclone) — bypass all local operations |
| `notifications` | `boolean` | `true` | Send sanitized alerts through the TUI/RPC companion. Events carry only a closed kind and bounded metadata (no paths, args, output, or explanations). Delivery is UX-only and never affects enforcement; if the RPC/TUI is unavailable, alerts are absent. |
| `redactionEnabled` | `boolean` | `true` | **Master kill switch** for in-place secret redaction. When `false`, Warden skips deepScan on tool inputs, regex+LLM redaction on tool outputs, and outbound scanning (`session.context`, `session.generate`, `session.title`, `session.compaction`) for **all** tools (the policy system part is still appended where applicable). File blocking, write-protection, LLM safety evaluation, env-var stripping, and audit logging remain enabled. Overrides `redactOnWrite` and `redactionExemptPaths` (both become no-ops). |
| `redactOnWrite` | `boolean` | `true` | When `false`, secret redaction is skipped for `write`/`edit`/`patch` tool inputs only. The file content is written as-is, and those already-recorded tool-call inputs are also exempt from outbound input redaction on `session.context`, `session.generate`, `session.title`, and `session.compaction`, so the original secret is forwarded to the provider. Useful for projects that embed real API keys in source code and accept the trade-off. Ignored when `redactionEnabled: false`. |
| `scanUserPrompts` | `boolean` | `false` *(opt-in)* | When `true`, incoming user prompts (and subtask prompts) plus **attachment metadata** are scanned via V2's `session.prompt` hook before they reach the LLM. Metadata covers file URI/name/description, agent/skill names, and mentions; file contents are never read. If a detected secret is found, prompt admission is **blocked** (the prompt never persists and never reaches the model). Default is `false` because the OpenCode TUI surfaces a generic `"Session error"` on blocked prompts — enable only if you accept that UX trade-off. See [User Prompt Scanning](#user-prompt-scanning). Ignored when `redactionEnabled: false`. |
| `redactionExemptPaths` | `string[]` | `[]` | Glob patterns of files where secret redaction is skipped for tool inputs (`write`/`edit`/`patch`, shell redirections, SSH/SCP/rsync/rclone uploads), tool outputs (`read`, shell `cat`/`head`/`tail`, remote downloads), and attributable outbound tool results on `session.context`/`session.generate`/`session.title`. Supports directory globs (e.g. `src/config/**`) and host-scoped entries (e.g. `host:web-*:/etc/myapp/**` for remote-only exemption). File blocking, write-protection, and LLM safety evaluation still apply. Each exemption is recorded in the audit log. Ignored when `redactionEnabled: false`. See [host-scoped syntax](#host-scoped-exempt-paths) below. |

### `audit` — Audit Logging

| Option | Type | Default | Description |
|---|---|---|---|
| `audit.enabled` | `boolean` | `true` | Enable file-based audit logging |
| `audit.filePath` | `string` | `".opencode/warden/audit.log"` | Log file path (relative to project root or absolute) |
| `audit.maxFileSize` | `number` | `10485760` (10 MB) | Maximum log file size before rotation |
| `audit.maxFiles` | `number` | `5` | Number of rotated log files to keep |
| `audit.verbosity` | `"quiet" \| "normal" \| "verbose"` | `"normal"` | Logging detail level |

Verbosity levels:
- **`quiet`**: Only blocked attempts
- **`normal`**: Blocks and detections
- **`verbose`**: Everything including clean passes

### `diagnosticLog` — Independent Diagnostics

Diagnostic logging is independent of the LLM and records hook start/end, decisions, and LLM chat traffic in a separate file.

| Option | Type | Default | Description |
|---|---|---|---|
| `diagnosticLog.enabled` | `boolean` | `false` | Enable the diagnostic log |
| `diagnosticLog.filePath` | `string` | `".opencode/warden/diagnostic.log"` | Diagnostic file path (relative to project root or absolute) |
| `diagnosticLog.maxFileSize` | `number` | `10485760` (10 MB) | Maximum size before rotation |
| `diagnosticLog.maxFiles` | `number` | `3` | Number of rotated files to keep |

When enabled, an additional `*-llm.log` file in the same directory records LLM chat traffic.

### `env` — Environment Sanitization

| Option | Type | Default | Description |
|---|---|---|---|
| `env.enabled` | `boolean` | `true` | Enable environment variable sanitization |
| `env.stripPatterns` | `string[]` | See [example config](#complete-example-configuration) | Env var name patterns to redact (supports `*` wildcard) |

### `indirectExecution` — Indirect Execution Prevention

| Option | Type | Default | Description |
|---|---|---|---|
| `indirectExecution.enabled` | `boolean` | `true` | Enable file content analysis before execution |
| `indirectExecution.scriptExtensions` | `string[]` | `.sh`, `.py`, `.js`, `.ts`, etc. | File extensions to intercept |
| `indirectExecution.systemPaths` | `string[]` | `/usr/bin/`, `/usr/local/bin/`, etc. | System paths to monitor |
| `indirectExecution.maxContentSize` | `number` | `65536` | Max file content size to analyze (bytes) |
| `indirectExecution.blockBinaries` | `boolean` | `true` | Block execution of binary files |
| `indirectExecution.interpreters` | `string[]` | `bash`, `python`, `node`, etc. | Interpreter commands to intercept |
| `indirectExecution.systemPrompt` | `string` | `""` | Custom system prompt (empty = built-in default) |
| `indirectExecution.promptTemplate` | `string` | `""` | Custom prompt template (empty = built-in default) |

### `llm` — LLM Integration

| Option | Type | Default | Description |
|---|---|---|---|
| `llm.enabled` | `boolean` | `false` | Master switch for all LLM features. When `false`, LLM components are absent by design; deterministic-only mode runs without outage blocking. |
| `llm.debug` | `boolean` | `true` | Verbose LLM debug logging |
| `llm.baseUrl` | `string` | `""` | LLM API base URL (OpenAI-compatible) — must be configured when LLM is enabled |
| `llm.model` | `string` | `""` | Model identifier — must be configured when LLM is enabled |
| `llm.apiKey` | `string` | `""` | API key for authentication |
| `llm.timeout` | `number` | `0` | Request timeout in milliseconds. `0` means no timeout; explicit values must be positive. Set one when enabling the LLM. |
| `llm.contextAccumulation` | `boolean` | `false` | Retain conversation history across evaluations |
| `llm.contextDetectionsOnly` | `boolean` | `true` | Only keep history entries with detections |
| `llm.maxContextPairs` | `number` | `5` | Maximum user+assistant pairs to retain |
| `llm.maxContextChars` | `number` | `16000` | Maximum total characters in context history |
| `llm.temperature` | `number` | `0` | LLM sampling temperature (0–2, lower = more deterministic) |
| `llm.headers` | `Record<string, string>` | `{}` | Custom HTTP headers (e.g., for Azure OpenAI) |
| `llm.healthCheckPath` | `string` | `""` | Endpoint for health checks (set explicitly, e.g. `/models`) |
| `llm.completionsPath` | `string` | `""` | Chat completions endpoint path (set explicitly, e.g. `/chat/completions`) |
| `llm.providers` | `Provider[]` | `[]` | Shared provider chain inherited by components without their own providers. Each provider has `name`, `cooldown`, endpoint fields, and `maxTokens` (default generation cap `32768`). |

**Fail-closed behavior:** With `llm.enabled: true`, an unavailable, misconfigured, timed-out, or garbage evaluator/sanitizer blocks the operation **regardless of `actionMode`** (`warn` and `permission` do not allow an outage through). A genuine model risk verdict may still follow `warn`; an evaluator failure may not. An enabled-but-null component for a tool in its configured list also blocks. Explicit `llm.enabled: false` (or an explicitly disabled component) is deterministic-only and does not block because of LLM absence.

### `llm.safetyEvaluator` — Input Safety Evaluation

| Option | Type | Default | Description |
|---|---|---|---|
| `safetyEvaluator.enabled` | `boolean` | `true` | Enable LLM-based safety evaluation |
| `safetyEvaluator.tools` | `string[]` | `["shell", "write", "edit", "patch", "read", "webfetch"]` | Tools to evaluate for safety. Legacy `bash` is accepted as an alias for `shell`. |
| `safetyEvaluator.blockThreshold` | `RiskLevel` | `"high"` | Block calls at or above this risk level |
| `safetyEvaluator.warnThreshold` | `RiskLevel` | `"medium"` | Warn at or above this risk level |
| `safetyEvaluator.bypassedCommands` | `string[]` | `["git status", "ls", "pwd", ...]` | Command prefixes that skip safety evaluation. Bypass is disqualified (evaluation forced) when the command contains an execution primitive (`eval`, `sh -c`, `$(...)`, `find -exec`, …), an unquoted shell comment (`#`), or a credential-surface / verdict-forgery finding (metadata endpoints, docker.sock, service-account tokens, embedded `Safe:/Risk Level:/Recommendation:` text). |
| `safetyEvaluator.systemPrompt` | `string` | `""` | Custom system prompt (empty = built-in default) |
| `safetyEvaluator.promptTemplate` | `string` | `""` | Custom prompt template (empty = built-in default) |
| `safetyEvaluator.actionMode` | `"block" \| "permission" \| "warn"` | `"block"` | How to handle dangerous tool calls |

Action modes:

| Mode | Behavior |
|---|---|
| `"block"` | Auto-block dangerous calls by throwing an error — the AI sees the block reason and can inform the user |
| `"permission"` | Integrate with OpenCode's permission system — deny on block, ask on warn, allow on allow, fall back to `"block"` if the permission hook doesn't fire |
| `"warn"` | Allow a genuine risky call to proceed after a warning — but an evaluator outage still blocks (fail-closed) |

### `llm.outputSanitizer` — Output Sanitization

| Option | Type | Default | Description |
|---|---|---|---|
| `outputSanitizer.enabled` | `boolean` | `true` | Enable LLM-based output sanitization |
| `outputSanitizer.tools` | `string[]` | `["read", "shell", "grep"]` | Tools whose output to sanitize. Legacy `bash` is accepted as an alias for `shell`. |
| `outputSanitizer.skipWhenRegexClean` | `boolean` | `false` | Skip LLM pass if regex found nothing |
| `outputSanitizer.systemPrompt` | `string` | `""` | Custom system prompt (empty = built-in default) |
| `outputSanitizer.promptTemplate` | `string` | `""` | Custom prompt template (empty = built-in default) |
| `outputSanitizer.actionMode` | `"redact" \| "warn" \| "pass"` | `"redact"` | How to handle detected secrets in output |

Action modes:

| Mode | Behavior |
|---|---|
| `"redact"` | Auto-redact secrets in output — secrets are replaced before the AI sees them |
| `"warn"` | Redact secrets AND always show a detailed notification with categories found (bypasses rate limiter) |
| `"pass"` | Don't redact — log detections only. This is an explicit detection-only debugging mode, not a secure default. |

If the LLM is enabled and the sanitizer is missing/unavailable for a tool in its list, output is withheld (`[BLOCKED]`) in `"redact"`/`"warn"` modes rather than released raw.

### `customPatterns` — Custom Detection Rules

Each custom pattern entry requires:

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique identifier |
| `name` | `string` | Human-readable name |
| `category` | `PatternCategory` | Category to group under |
| `pattern` | `string` | Regular expression (as string) |
| `redactTemplate` | `string` | Replacement text (e.g., `"[INTERNAL-KEY]"`) |
| `confidence` | `"low" \| "medium" \| "high"` | Detection confidence level |

## Complete Example Configuration

This example shows the commonly used options with explanatory comments. In practice, you only need to specify the options you want to override.

```jsonc
{
  // ── Category Control ──
  // Enable or disable entire detection categories
  "categories": {
    "api-keys": true,
    "credentials": true,
    "private-keys": true,
    "docker": true,
    "kubernetes": true,
    "cloud": true,
    "pii-email": true,
    "pii-phone": true,
    "pii-ssn": true,
    "pii-credit-card": true,
    "pii-ip-address": false
  },

  // ── Pattern Control ──
  // Disable specific built-in patterns by ID
  "disabledPatterns": [
    "generic-bearer-token"
  ],

  // Add custom detection rules
  "customPatterns": [
    {
      "id": "internal-api-key",
      "name": "Internal API Key",
      "category": "api-keys",
      "pattern": "ikey_[A-Za-z0-9]{32,}",
      "redactTemplate": "[INTERNAL-KEY-REDACTED]",
      "confidence": "high"
    },
    {
      "id": "company-secret",
      "name": "Company Secret Token",
      "category": "credentials",
      "pattern": "ACME_SECRET_[A-Za-z0-9_]+=[^\\s]+",
      "redactTemplate": "ACME_SECRET_****=[REDACTED]",
      "confidence": "medium"
    }
  ],

  // ── File Access Control ──
  // Exact paths that bypass the blocked list (not globs)
  "whitelistedPaths": [
    "/home/you/project/example.env",
    "/home/you/project/.env.example"
  ],

  // Files blocked from tool access (glob patterns)
  "blockedFilePaths": [
    "**/.env",
    "**/.env.*",
    "**/.env.local",
    "**/.env.production",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.jks",
    "**/id_rsa",
    "**/id_ed25519",
    "**/id_ecdsa",
    "**/.aws/credentials",
    "**/.aws/config",
    "**/.docker/config.json",
    "**/.kube/config",
    "**/kubeconfig*",
    "**/values.secret.yaml",
    "**/values.secrets.yaml",
    "**/*.tfstate",
    "**/*.tfvars",
    "**/.vault-token",
    "**/.netrc",
    "**/.pgpass",
    "**/.my.cnf"
  ],

  // Files that may be READ but never WRITTEN by the agent.
  // Write attempts via write/edit tools AND shell redirections
  // (>, >>, tee, truncate, dd of=) are deterministically blocked.
  // Reads (cat, tail, head, grep) remain allowed.
  "writeProtectedPaths": [
    "**/var/log/**"
  ],

  // Files where secret redaction is SKIPPED for write/edit/patch inputs
  // and read outputs. Use this when your source code legitimately contains
  // API keys (client libraries, config templates, test fixtures).
  // File blocking, write-protection, and LLM safety evaluation still apply —
  // only in-place secret redaction is skipped. Each exemption is logged.
  "redactionExemptPaths": [
    "src/config.ts",
    "**/secrets.example.json"
  ],

  // ── Secret Redaction Switches ──
  // Master kill switch. When false, ALL in-place secret redaction is skipped
  // (input deepScan + output regex + LLM sanitizer for every tool).
  // File blocking, write-protection, env stripping, and LLM safety eval
  // remain enabled. Overrides the two knobs below.
  "redactionEnabled": true,

  // When false, skip redaction on write/edit/patch tool inputs only.
  // Useful for projects that embed real API keys throughout source code.
  "redactOnWrite": true,

  // ── Tool Control ──
  // Tools to skip Warden processing entirely (not hidden; use blockedTools to hide)
  "excludedTools": [],

  // Tools to block entirely (alias-aware: shell/bash, subagent/task)
  "blockedTools": [],

  // Sanitized TUI/RPC alerts (fixed kind + bounded metadata; UX only).
  // Enforcement never depends on delivery success.
  "notifications": true,

  // ── Audit Logging ──
  "audit": {
    "enabled": true,
    "filePath": ".opencode/warden/audit.log",
    "maxFileSize": 10485760,
    "maxFiles": 5,
    "verbosity": "normal"
  },

  // Independent diagnostic logging (includes a separate *-llm.log)
  "diagnosticLog": {
    "enabled": false,
    "filePath": ".opencode/warden/diagnostic.log",
    "maxFileSize": 10485760,
    "maxFiles": 3
  },

  // ── Environment Sanitization ──
  "env": {
    "enabled": true,
    "stripPatterns": [
      "*_SECRET",
      "*_SECRET_*",
      "*_TOKEN",
      "*_TOKEN_*",
      "*_PASSWORD",
      "*_PASSWORD_*",
      "*_KEY",
      "*_API_KEY",
      "*_API_KEY_*",
      "*_PRIVATE_KEY",
      "DOCKER_AUTH_*",
      "AWS_SECRET_ACCESS_KEY",
      "AWS_SESSION_TOKEN",
      "GITHUB_TOKEN",
      "VAULT_TOKEN",
      "PULUMI_CONFIG_PASSPHRASE",
      "HEROKU_API_KEY",
      "VERCEL_TOKEN",
      "CF_API_TOKEN",
      "CF_API_KEY",
      "SUPABASE_SERVICE_ROLE_KEY",
      "DATABASE_URL",
      "REDIS_URL",
      "MONGODB_URI"
    ]
  },

  // ── LLM Integration ──
  "llm": {
    "enabled": true,
    "debug": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "your-model-name",
    "apiKey": "",
    "timeout": 10000,
    "contextAccumulation": false,
    "contextDetectionsOnly": true,
    "maxContextPairs": 5,
    "maxContextChars": 16000,
    "temperature": 0.1,
    "headers": {},
    "healthCheckPath": "/models",
    "completionsPath": "/chat/completions",

    // Output Sanitization (LLM second-pass after regex)
    "outputSanitizer": {
      "enabled": true,
      "tools": ["read", "shell", "grep"],
      "skipWhenRegexClean": false,
      "systemPrompt": "",
      "promptTemplate": "",
      "actionMode": "redact"
    },

    // Safety Evaluation (risk assessment for tool calls)
    "safetyEvaluator": {
      "enabled": true,
      "tools": ["shell", "write", "edit", "patch", "read", "webfetch"],
      "blockThreshold": "high",
      "warnThreshold": "medium",
      "bypassedCommands": [
        "git status",
        "git log",
        "git diff",
        "git branch",
        "git show",
        "ls",
        "pwd",
        "echo",
        "cat",
        "head",
        "tail",
        "wc",
        "date",
        "whoami"
      ],
      "systemPrompt": "",
      "promptTemplate": "",
      "actionMode": "block"
    }
  }
}
```

> **Note**: JSON does not support comments. The `jsonc` format above is for documentation purposes. Remove all comments before using in a real config file.

## Enforcement Layers and Limits

### Outbound request scanning (context, generate, title, compaction)

Before each primary provider request, Warden's `session.context` hook:

- appends the security policy to the request-local system prompt (per request; never written to stored history),
- removes `blockedTools` from the request's tool definitions,
- redacts supported text: system parts, message `text`/`reasoning`/`compaction`, and tool-result text/JSON string values.

`session.generate` reuses the full session context (agent, tools, system, messages) and applies the same policy append, blocked-tool removal, and deterministic redaction as a primary request. `session.title` is a tool-less naming request: Warden redacts its system/messages deterministically but deliberately does not append the security policy, preserving title output. `session.compaction` applies the same policy and scanning to the native summary request; its 2.0.18 policy/redaction pass with a valid summary is unchanged.

It preserves tool-call ids/names, message metadata, and `providerMetadata` so tool pairing and provider replay metadata stay valid. Historical tool-call input strings are structurally redacted in the request projection: argument keys, call ids/names, and object/array shape are preserved, and only detected string leaves change. File/media identifiers are scanned read-only; a detection withholds the request because rewriting a reference would corrupt provider pairing. Provider-signed/encrypted text or metadata-sensitive tool-call input is never rewritten: a required redaction aborts the request (fail-closed) rather than leaving an invalid signature. History on disk is unchanged — redaction is applied to the per-request projection. A scanner failure or unsupported shape also throws and aborts request preparation.

**Secret-bearing writes and at-rest input.** `write`/`edit`/`patch` input redaction changes what is written to disk, but the host persists the model's original tool-call input before `tool.execute.before` runs. On the next primary dispatch, Warden structurally redacts detected strings in that historical tool-call input for the provider request (ids/names/keys/shape preserved), so the secret is not forwarded. Warden does **not** scrub the raw input from the session database: request-projection redaction is not at-rest scrubbing. Provider-signed/encrypted or unsupported shapes abort instead of being forwarded. `redactOnWrite: false` and `redactionExemptPaths` exempt those historical inputs and allow the original through, so they are not a secure remedy. Avoid routing real secrets through model-authored writes. A bounded 2.0.18 replay passed with this structural projection (exit 0, next request redacted, policy present); raw pre-hook input remains at rest and this is not a broad certification.

### Global shell backstop

`shell.create.before` checks every shell creation, not only agent tool calls. Configured `blockedFilePaths` and `writeProtectedPaths` therefore also prevent the **user's own terminals/background shells** from reading or writing those paths. This is intentional and broader than agent-only enforcement. The backstop is deterministic (no LLM), resolves relative `cwd` against the workspace directory, checks SSH/SCP/rsync/rclone remote paths, and skips dynamic targets (`$VAR`, backticks) because user shells cannot be resolved without executing them.

### Session deny rules (defense in depth)

Warden also translates exactly representable policy into session-scoped deny rules:

- literal `blockedTools` → canonical + alias deny rules;
- literal **absolute** `blockedFilePaths` → read and write actions;
- literal **absolute** `writeProtectedPaths` → write actions only.

Configured glob, relative, `~`, `host:` entries, permission wildcards, and shell path policy are omitted because OpenCode's permission matcher is not Warden's glob matcher. Whitelisted paths are never emitted. For an absolute path inside the project directory, Warden emits both the absolute path and the host's project-relative resource; paths outside emit the absolute resource. `session.update({ permissions })` replaces the host ruleset, so Warden re-reads and appends missing rules, then re-reads again immediately before writing and defers if the host changed meanwhile (the API has no compare-and-set, so the race is narrowed, not eliminated). Read/update failures are logged and ignored. These rules are not the primary guard: `tool.execute.before`, `permission.evaluate`, the shell backstop, and output redaction remain authoritative, and a failed sync never changes an allow/deny decision. Preservation of pre-existing host rules and application of the appended rules both passed on 2.0.18; newer-host behavior is source-verified only.

### Hook ordering and trust

OpenCode runs hooks in registration order and provides no priority API. Later plugins observe earlier mutations, so Warden cannot guarantee its mutations are final. Treat the host and all loaded plugins as trusted, and load Warden last where possible. Registration order alone is not a security boundary.

### Notifications are UX-only

V2 server plugins have no toast or structured app-log channel. The entrypoint wires hook notifications to `src/tui-notifications.ts`, which emits a strict event-only RPC contract; the shipped `./tui` companion subscribes and renders fixed copy. Events contain only a closed `kind`, an optional canonical tool id, and an optional bounded count — never paths, arguments, output, explanations, or raw audit text. Registration/delivery failure is non-blocking, and a slow/absent TUI cannot delay setup or affect a decision. Server-side RPC/SSE registration and real event delivery passed on 2.0.18; **live rendered TUI toasts were not tested**. Audit/diagnostic files remain the durable record, with the short-lived CLI flush caveat noted in [Audit Logging](audit-logging.md). On 2.0.18 a blocked file read was classified as RPC `kind: "denied"` rather than `"blocked"`; this is UX-only.

## Host-Scoped Exempt Paths

By default, entries in `redactionExemptPaths` apply only to **local** filesystem operations. To skip redaction on **remote** operations (SSH/SCP/rsync/rclone), prefix the entry with `host:`:

| Entry form | Scope | Example |
|---|---|---|
| `path` or `glob` | LOCAL filesystem only | `src/config.ts`, `**/secrets.json` |
| `host:*:path` | Any remote host | `host:*:/etc/myapp/config.conf` |
| `host:<glob>:path` | Remote hosts matching the host glob | `host:web-*:/var/app/**` |
| `host:<exact>:path` | One specific host | `host:prod-01.example.com:/etc/specific.conf` |

```json
{
  "redactionExemptPaths": [
    "src/config.ts",                                   // local only
    "**/fixtures/*.json",                              // local only
    "host:web-*:/etc/myapp/**",                        // any host matching web-*
    "host:prod-01.example.com:/var/secrets.conf"       // one specific host
  ]
}
```

**Why scoping?** A full path like `/etc/myapp/config.conf` could exist on both your local machine and a remote server, with different contents. Without the `host:` prefix, the entry would silently fail to apply to remote operations (or worse, you'd think it did). The `host:` prefix makes the intent explicit and avoids ambiguity.

**How Warden knows the host:** When you run `ssh user@web-01 "cat /etc/foo"`, the parser extracts `host: "web-01"`. The same applies to `scp`, `rsync`, `rclone`. The user portion (`user@`) is ignored for matching — only the host glob is checked.

**Mixed configs:** You can freely mix local and `host:` entries in the same `redactionExemptPaths` array. Local entries apply to local ops; `host:` entries apply to remote ops. There is no overlap.

## User Prompt Scanning

**Opt-in feature** — set `scanUserPrompts: true` to enable. Disabled by default because of UX limitations explained below.

When enabled, Warden scans every incoming user prompt (and subtask prompt) plus attachment **metadata** via V2's `session.prompt` hook before it reaches the LLM. File attachment contents are never read or decoded. If a detected secret is found:

- Prompt admission is **blocked** — the prompt is never persisted to session storage and never sent to the model
- The failure aborts prompt preparation (OpenCode has no typed failure channel for this hook)
- The TUI shows a generic `"Session error"` message (this is an OpenCode limitation — see [Blocking UX](#blocking-ux) below)
- The session remains usable — subsequent prompts work normally

Attachment metadata scanned: file `uri` (except inline `data:` content), `name`, `description`; agent `name`; skill `id`/`name`; and `mention.text` on each. This runs under the same `scanUserPrompts` + `redactionEnabled` opt-in gates.

This is the earliest interception point in the Warden pipeline. It runs **before** `tool.execute.before` because it fires before any tool call exists.

The master switch `redactionEnabled` (default `true`) gates this feature too: when `false`, prompt scanning is skipped regardless of `scanUserPrompts`.

```json
{
  "scanUserPrompts": true
}
```

### Blocking UX

When Warden blocks a prompt by throwing, the OpenCode TUI surfaces a generic `"Session error"` message regardless of the error message. **The detailed reason (which secret pattern was detected, count, etc.) is preserved in the audit/diagnostic log but not in the TUI.**

To see why a prompt was blocked:

1. Run the `security_report` tool (asks Warden for a session summary), or
2. Inspect `.opencode/warden/audit.log` directly (look for entries with `hook: "chat.message"` and `blocked: true`)

The audit entry's `blockReason` field contains the full pattern list and category breakdown. V2 has no reliable server toast for this path; the wired TUI/RPC bridge can show a fixed alert, but the detailed reason remains in the audit/diagnostic log.

This UX limitation is why the feature ships **opt-in** — users who enable it accept the trade-off (stronger security, less friendly blocking feedback) in exchange for the extra defense layer.

## Minimal Configurations

**Regex-only mode** (no LLM, zero setup):

```json
{}
```

That's it. All defaults apply — 65 active patterns, file blocking enabled, audit logging on.

**LLM mode** (safety evaluation + output sanitization):

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "your-model-name",
    "timeout": 60000
  }
}
```

With the LLM enabled, an unavailable evaluator/sanitizer blocks LLM-evaluated operations regardless of `actionMode`. To run deterministically without LLM outage blocking, leave `llm.enabled` at `false` (the default).

**With local LLM** (e.g., Ollama, llama.cpp, vLLM):

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "llama3"
  }
}
```

**With Azure OpenAI**:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "https://your-resource.openai.azure.com/openai/deployments/gpt-4",
    "model": "gpt-4",
    "headers": {
      "api-key": "your-azure-api-key"
    },
    "completionsPath": "/chat/completions?api-version=2024-02-15-preview"
  }
}
```

**User-prompted permission mode**:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "your-model",
    "safetyEvaluator": {
      "actionMode": "permission"
    }
  }
}
```

**SSH-only mode** (monitor only remote machine operations):

```json
{
  "sshOnlyMode": true
}
```

When enabled, only commands involving remote machines are monitored:
- All local file reads, edits, and other tool calls bypass security entirely
- Environment variable sanitization is skipped
- Only `ssh`, `scp`, `sftp`, `rsync`, and `rclone` command outputs are scanned and redacted

**Keeping legitimate API keys in source code** (e.g., a client library, config template, or test fixture):

```json
{
  "redactionExemptPaths": [
    "src/openrouter-client.ts",
    "**/fixtures/*.json"
  ]
}
```

Warden will not rewrite detected secrets to `[REDACTED]` when the agent writes to or reads from these paths. Coverage includes:
- `write`/`edit`/`patch` tool inputs (all patch targets)
- `read` tool outputs
- Shell redirections (`>`, `>>`, `tee`, `truncate`) and reads (`cat`, `head`, `tail`) on matching paths
- Attributable outbound tool results on `session.context`/`session.generate`/`session.title` that came from a read
- SSH/SCP/rsync/rclone uploads and downloads on matching hosts (use `host:` prefix — see [Host-Scoped Exempt Paths](#host-scoped-exempt-paths))

File blocking (`blockedFilePaths`), write-protection (`writeProtectedPaths`), and LLM safety evaluation still apply — only secret redaction is skipped. Every exemption is recorded in the audit log for transparency.

**Embedding real API keys throughout source code** (e.g., a personal project where you accept the trade-off):

```json
{
  "redactOnWrite": false
}
```

Skips redaction on `write`/`edit`/`patch` inputs only — shell commands and read outputs are still redacted. Historical tool-call inputs for those three tools are also exempt from outbound input redaction on context/generate/title/compaction, so the original secret is forwarded; shell input secrets are still redacted or blocked. Prefer `redactionExemptPaths` for scoped exemptions; this flag is the broader hammer.

**Disable all secret redaction entirely** (debugging, or you've decided other layers are enough):

```json
{
  "redactionEnabled": false
}
```

Skips input deepScan, output regex+LLM redaction, and outbound scanning on context/generate/title/compaction for **every** tool (the policy system part is still appended where applicable). File blocking, write-protection, env-var stripping, LLM safety evaluation, and audit logging remain enabled. `redactOnWrite` and `redactionExemptPaths` become no-ops when this is `false`.

**SSH-only mode with LLM safety** (monitor remote operations + LLM risk evaluation):

```json
{
  "sshOnlyMode": true,
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "your-model"
  }
}
```
