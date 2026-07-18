# Configuration

[← Back to README](../README.md)

## Configuration Hierarchy

Warden loads configuration from three layers, each deep-merging into the previous:

| Priority | Location | Scope |
|---|---|---|
| 1 (lowest) | Built-in defaults | Always applied |
| 2 | `~/.config/opencode/opencode-warden.json` | Global — applies to all projects |
| 3 (highest) | `.opencode/opencode-warden.json` | Project-specific — overrides global |

**Deep merge** means you only need to specify the fields you want to override. Unspecified fields inherit from the layer below.

**Global config** is ideal for settings that apply everywhere — your LLM endpoint, personal PII preferences, custom company patterns.

**Project config** is ideal for project-specific overrides — additional blocked paths, allowlisted files, project-specific tools to monitor.

## Full Configuration Reference

### Root Options

| Option | Type | Default | Description |
|---|---|---|---|
| `categories` | `Record<PatternCategory, boolean>` | All `true` except `pii-ip-address` | Enable or disable detection categories |
| `disabledPatterns` | `string[]` | `[]` | Pattern IDs to disable (e.g., `["generic-bearer-token"]`) |
| `customPatterns` | `CustomPatternConfig[]` | `[]` | User-defined detection patterns |
| `whitelistedPaths` | `string[]` | `[]` | Glob patterns that bypass file blocking |
| `blockedFilePaths` | `string[]` | See [defaults](#default-blocked-file-paths) | Glob patterns of files to block **both read and write** (secrets, keys, credentials) |
| `writeProtectedPaths` | `string[]` | `["**/var/log/**"]` | Glob patterns of files that may be **read but not written** (logs, state files). Closes the anti-forensics hole (log truncation) deterministically. Write attempts via `write`/`edit` tools and shell redirections (`>`, `>>`, `tee`, `truncate`, `dd of=`) are blocked. |
| `excludedTools` | `string[]` | `["glob", "list"]` | Tools to skip entirely (no scanning, no blocking) |
| `blockedTools` | `string[]` | `[]` | Tools to block entirely (always throws when called) |
| `sshOnlyMode` | `boolean` | `false` | Only monitor remote commands (ssh, scp, sftp, rsync, rclone) — bypass all local operations |
| `notifications` | `boolean` | `true` | Show toast notifications in the TUI |
| `redactionEnabled` | `boolean` | `true` | **Master kill switch** for in-place secret redaction. When `false`, Warden skips deepScan on tool inputs AND regex+LLM redaction on tool outputs for **all** tools. File blocking, write-protection, LLM safety evaluation, env-var stripping, and audit logging remain enabled. Overrides `redactOnWrite` and `redactionExemptPaths` (both become no-ops). |
| `redactOnWrite` | `boolean` | `true` | When `false`, secret redaction is skipped for `write`/`edit`/`patch` tool inputs only. The file content is written as-is. Useful for projects that embed real API keys in source code and accept the trade-off. Ignored when `redactionEnabled: false`. |
| `scanUserPrompts` | `boolean` | `false` *(opt-in)* | When `true`, incoming user prompts (and subtask prompts) are scanned via OpenCode's `chat.message` hook before they reach the LLM. If a detected secret is found, message creation is **blocked** (the prompt never persists and never reaches the model). Default is `false` because the OpenCode TUI surfaces a generic `"Session error"` toast on blocked prompts — enable only if you accept that UX trade-off. See [User Prompt Scanning](#user-prompt-scanning). Ignored when `redactionEnabled: false`. |
| `redactionExemptPaths` | `string[]` | `[]` | Glob patterns of files where secret redaction is skipped for tool inputs (`write`/`edit`/`patch`, bash redirections, SSH/SCP/rsync/rclone uploads) and tool outputs (`read`, bash `cat`/`head`/`tail`, remote downloads). Supports directory globs (e.g. `src/config/**`) and host-scoped entries (e.g. `host:web-*:/etc/myapp/**` for remote-only exemption). File blocking, write-protection, and LLM safety evaluation still apply. Each exemption is recorded in the audit log. Ignored when `redactionEnabled: false`. See [host-scoped syntax](#host-scoped-exempt-paths) below. |

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

### `env` — Environment Sanitization

| Option | Type | Default | Description |
|---|---|---|---|
| `env.enabled` | `boolean` | `true` | Enable environment variable sanitization |
| `env.stripPatterns` | `string[]` | See [defaults](#default-env-strip-patterns) | Env var name patterns to redact (supports `*` wildcard) |

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
| `llm.enabled` | `boolean` | `false` | Master switch for all LLM features |
| `llm.debug` | `boolean` | `true` | Verbose LLM debug logging |
| `llm.baseUrl` | `string` | `""` | LLM API base URL (OpenAI-compatible) — must be configured when LLM is enabled |
| `llm.model` | `string` | `""` | Model identifier — must be configured when LLM is enabled |
| `llm.apiKey` | `string` | `""` | API key for authentication |
| `llm.timeout` | `number` | `10000` | Request timeout in milliseconds |
| `llm.contextAccumulation` | `boolean` | `false` | Retain conversation history across evaluations |
| `llm.contextDetectionsOnly` | `boolean` | `true` | Only keep history entries with detections |
| `llm.maxContextPairs` | `number` | `5` | Maximum user+assistant pairs to retain |
| `llm.maxContextChars` | `number` | `16000` | Maximum total characters in context history |
| `llm.temperature` | `number` | `0.1` | LLM sampling temperature (0–2, lower = more deterministic) |
| `llm.headers` | `Record<string, string>` | `{}` | Custom HTTP headers (e.g., for Azure OpenAI) |
| `llm.healthCheckPath` | `string` | `"/models"` | Endpoint for health checks |
| `llm.completionsPath` | `string` | `"/chat/completions"` | Chat completions endpoint path |

### `llm.safetyEvaluator` — Input Safety Evaluation

| Option | Type | Default | Description |
|---|---|---|---|
| `safetyEvaluator.enabled` | `boolean` | `true` | Enable LLM-based safety evaluation |
| `safetyEvaluator.tools` | `string[]` | `["bash", "write", "edit", "webfetch"]` | Tools to evaluate for safety |
| `safetyEvaluator.blockThreshold` | `RiskLevel` | `"high"` | Block calls at or above this risk level |
| `safetyEvaluator.warnThreshold` | `RiskLevel` | `"medium"` | Warn at or above this risk level |
| `safetyEvaluator.bypassedCommands` | `string[]` | `["git status", "ls", "pwd", ...]` | Command prefixes that skip safety evaluation |
| `safetyEvaluator.systemPrompt` | `string` | `""` | Custom system prompt (empty = built-in default) |
| `safetyEvaluator.promptTemplate` | `string` | `""` | Custom prompt template (empty = built-in default) |
| `safetyEvaluator.actionMode` | `"block" \| "permission" \| "warn"` | `"block"` | How to handle dangerous tool calls |

Action modes:

| Mode | Behavior |
|---|---|
| `"block"` | Auto-block dangerous calls by throwing an error — the AI sees the block reason and can inform the user |
| `"permission"` | Integrate with OpenCode's permission system — auto-deny critical risks, prompt the user for high/medium risks with a risk assessment, fall back to `"block"` if the permission hook doesn't fire |
| `"warn"` | Show a toast warning but allow the call to proceed — useful for monitoring without disruption |

### `llm.outputSanitizer` — Output Sanitization

| Option | Type | Default | Description |
|---|---|---|---|
| `outputSanitizer.enabled` | `boolean` | `true` | Enable LLM-based output sanitization |
| `outputSanitizer.tools` | `string[]` | `["read", "bash", "grep"]` | Tools whose output to sanitize |
| `outputSanitizer.skipWhenRegexClean` | `boolean` | `false` | Skip LLM pass if regex found nothing |
| `outputSanitizer.systemPrompt` | `string` | `""` | Custom system prompt (empty = built-in default) |
| `outputSanitizer.promptTemplate` | `string` | `""` | Custom prompt template (empty = built-in default) |
| `outputSanitizer.actionMode` | `"redact" \| "warn" \| "pass"` | `"redact"` | How to handle detected secrets in output |

Action modes:

| Mode | Behavior |
|---|---|
| `"redact"` | Auto-redact secrets in output — secrets are replaced before the AI sees them |
| `"warn"` | Redact secrets AND always show a detailed toast with categories found (bypasses rate limiter) |
| `"pass"` | Don't redact — just log detections for debugging and testing purposes |

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

This example shows **every available option** with explanatory comments. In practice, you only need to specify the options you want to override.

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
  // Paths that bypass the blocked list
  "whitelistedPaths": [
    "**/example.env",
    "**/.env.example"
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
  // Tools to skip entirely (no scanning, no blocking)
  "excludedTools": ["glob", "list"],

  // Show toast notifications in the TUI
  "notifications": true,

  // ── Audit Logging ──
  "audit": {
    "enabled": true,
    "filePath": ".opencode/warden/audit.log",
    "maxFileSize": 10485760,
    "maxFiles": 5,
    "verbosity": "normal"
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
      "tools": ["read", "bash", "grep"],
      "skipWhenRegexClean": false,
      "systemPrompt": "",
      "promptTemplate": "",
      "actionMode": "redact"
    },

    // Safety Evaluation (risk assessment for tool calls)
    "safetyEvaluator": {
      "enabled": true,
      "tools": ["bash", "write", "edit", "webfetch"],
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

When enabled, Warden scans every incoming user prompt (and subtask prompt) via OpenCode's `chat.message` hook before it reaches the LLM. If a detected secret is found:

- The message is **blocked** — the prompt is never persisted to session storage and never sent to the model
- A `Session.Event.Error` is published with Warden's reason (visible in audit logs)
- The TUI shows a generic `"Session error"` toast (this is an OpenCode limitation — see [Blocking UX](#blocking-ux) below)
- The session remains usable — subsequent prompts work normally

This is the earliest interception point in the Warden pipeline. It runs **before** `tool.execute.before` because it fires before any tool call exists.

The master switch `redactionEnabled` (default `true`) gates this feature too: when `false`, prompt scanning is skipped regardless of `scanUserPrompts`.

```json
{
  "scanUserPrompts": true
}
```

### Blocking UX

When Warden blocks a prompt by throwing, the OpenCode TUI surfaces a generic `"Session error"` toast regardless of the error message. **The detailed reason (which secret pattern was detected, count, etc.) is preserved in the audit log but not in the toast.**

This is an upstream UX limitation in OpenCode's `notifications.ts` plugin — it hardcodes `"Session error"` for unrecognized error types. To see why a prompt was blocked:

1. Run the `security_report` tool (asks Warden for a session summary), or
2. Inspect `.opencode/warden/audit.log` directly (look for entries with `hook: "chat.message"` and `blocked: true`)

The audit entry's `blockReason` field contains the full pattern list and category breakdown.

This UX limitation is why the feature ships **opt-in** — users who enable it accept the trade-off (stronger security, less friendly blocking feedback) in exchange for the extra defense layer.

## Minimal Configurations

**Regex-only mode** (no LLM, zero setup):

```json
{}
```

That's it. All defaults apply — 74 patterns active, file blocking enabled, audit logging on.

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
- `write`/`edit`/`patch` tool inputs
- `read` tool outputs
- Bash redirections (`>`, `>>`, `tee`, `truncate`) and reads (`cat`, `head`, `tail`) on matching paths
- SSH/SCP/rsync/rclone uploads and downloads on matching hosts (use `host:` prefix — see [Host-Scoped Exempt Paths](#host-scoped-exempt-paths))

File blocking (`blockedFilePaths`), write-protection (`writeProtectedPaths`), and LLM safety evaluation still apply — only secret redaction is skipped. Every exemption is recorded in the audit log for transparency.

**Embedding real API keys throughout source code** (e.g., a personal project where you accept the trade-off):

```json
{
  "redactOnWrite": false
}
```

Skips redaction on `write`/`edit`/`patch` inputs only — bash commands and read outputs are still redacted. Prefer `redactionExemptPaths` for scoped exemptions; this flag is the broader hammer.

**Disable all secret redaction entirely** (debugging, or you've decided other layers are enough):

```json
{
  "redactionEnabled": false
}
```

Skips input deepScan AND output regex+LLM redaction for **every** tool. File blocking, write-protection, env-var stripping, LLM safety evaluation, and audit logging remain enabled. `redactOnWrite` and `redactionExemptPaths` become no-ops when this is `false`.

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
