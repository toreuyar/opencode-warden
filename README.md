# OpenCode Warden

[![Tests](https://github.com/toreuyar/opencode-warden/actions/workflows/test.yml/badge.svg)](https://github.com/toreuyar/opencode-warden/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OpenCode Plugin](https://img.shields.io/badge/OpenCode-Plugin-8B5CF6)](https://opencode.ai)
[![Bun](https://img.shields.io/badge/Runtime-Bun-f9f1e1)](https://bun.sh)

A comprehensive security plugin for [OpenCode](https://opencode.ai) that intercepts tool calls to detect secrets, redact sensitive data, evaluate safety risks, block access to sensitive files, and maintain a complete audit trail — all in real time, as your AI coding assistant works.

## Table of Contents

- [Why Security Guard?](#why-security-guard)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Configuration Hierarchy](#configuration-hierarchy)
  - [Full Configuration Reference](#full-configuration-reference)
  - [Complete Example Configuration](#complete-example-configuration)
- [How It Works](#how-it-works)
  - [Hook Pipeline](#hook-pipeline)
  - [Detection Engine](#detection-engine)
  - [LLM Integration](#llm-integration)
  - [Customizing Prompts](#customizing-prompts)
  - [Action Modes](#action-modes)
  - [Permission System Integration](#permission-system-integration)
- [Built-in Tools](#built-in-tools)
- [Detection Patterns](#detection-patterns)
- [Audit Logging](#audit-logging)
- [Environment Sanitization](#environment-sanitization)
- [Example Use Cases](#example-use-cases)
- [Contributing](#contributing)
- [License](#license)

## Why Security Guard?

AI coding assistants are powerful — they read files, run shell commands, edit code, and fetch from the web. But with that power comes risk:

- Your `.env` file contains production database credentials — what if the AI reads it and echoes the password?
- A tool call runs `curl` with your API key embedded in the URL — that key is now in your conversation history.
- The AI writes a shell command that could delete critical files or exfiltrate data.
- Secrets leak into outputs, logs, and session transcripts.

**Security Guard** sits between OpenCode and every tool call, acting as a real-time firewall. It scans inputs before execution, redacts outputs after execution, evaluates commands for safety risks, and blocks access to sensitive files — all without slowing you down.

## Features

- **74 built-in detection patterns** across 11 categories — API keys, credentials, private keys, PII, cloud provider secrets, Docker, Kubernetes, and more
- **Deep recursive scanning** of nested tool arguments and outputs
- **File path blocking** with glob patterns — prevents access to `.env`, `*.pem`, `*.key`, kubeconfig, tfstate, and other sensitive files
- **LLM-powered safety evaluation** — analyzes tool calls across 10 risk dimensions (exfiltration, destruction, privilege escalation, etc.)
- **LLM-enhanced output sanitization** — catches context-dependent secrets that regex alone misses
- **Configurable action modes** — choose between auto-block, user-prompted permission, or warn-only for both input safety and output sanitization
- **Permission system integration** — hooks into OpenCode's native permission prompts to give users informed choices with risk assessments
- **Environment variable sanitization** — strips secrets from the shell environment before they reach tool calls
- **Custom detection rules** — add your own regex patterns at runtime, persisted to config
- **Comprehensive audit logging** — JSON-line log files with rotation, verbosity levels, and session statistics
- **Real-time toast notifications** — rate-limited alerts when secrets are detected or commands are blocked
- **Security policy injection** — informs the AI about active security policies so it can work within constraints
- **Session compaction context** — preserves security awareness across context window compressions
- **SSH-only mode** — monitor only remote commands (ssh, scp, sftp, rsync, rclone) while bypassing all local operations
- **3 built-in tools** — dashboard, reports, and rules management
- **Zero-config operation** — works out of the box with sensible defaults, no LLM required

## Installation

### Prerequisites

- [OpenCode](https://opencode.ai) v0.1.0 or later
- [Bun](https://bun.sh) runtime (OpenCode uses Bun for plugins)

### Install from npm (Recommended)

Add `opencode-warden` to the `plugin` array in your OpenCode configuration:

**Global** (`~/.config/opencode/opencode.json`) — applies to all projects:

```json
{
  "plugin": ["opencode-warden"]
}
```

**Project-level** (`./opencode.json`) — applies to a single project:

```json
{
  "plugin": ["opencode-warden"]
}
```

OpenCode automatically installs the package via Bun when it starts.

### Install from Source

If you prefer to run from source (for development or customization):

```bash
git clone https://github.com/toreuyar/opencode-warden.git
cd opencode-warden
bun install
```

Then register the plugin by adding its **absolute path** to `opencode.json`:

```json
{
  "plugin": [
    "/absolute/path/to/opencode-warden"
  ]
}
```

> **Note**: The path must be absolute (e.g., `/home/user/opencode-warden` on Linux, `/Users/user/opencode-warden` on macOS). A wrong or non-existent path will cause OpenCode to hang on startup.

### Alternative: Plugin Directory

You can also copy or symlink the plugin source into OpenCode's plugin directories:

- **Global**: `~/.config/opencode/plugins/`
- **Project-level**: `.opencode/plugins/`

Files placed in these directories are loaded automatically.

## Quick Start

Security Guard works with **zero configuration**. Once installed, it immediately:

1. Blocks access to sensitive files (`.env`, `*.pem`, `*.key`, etc.)
2. Scans and redacts secrets in tool inputs and outputs using 74 regex patterns
3. Sanitizes environment variables before they reach shell commands
4. Logs all security events to `.opencode/security-guard/audit.log`
5. Shows toast notifications when secrets are detected or blocked

To enable LLM-powered safety evaluation (recommended for production use), create a config file:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "your-model-name"
  }
}
```

Place this file at `.opencode/opencode-warden.json` in your project root or `~/.config/opencode/opencode-warden.json` for global settings.

## Configuration

### Configuration Hierarchy

Security Guard loads configuration from three layers, each deep-merging into the previous:

| Priority | Location | Scope |
|---|---|---|
| 1 (lowest) | Built-in defaults | Always applied |
| 2 | `~/.config/opencode/opencode-warden.json` | Global — applies to all projects |
| 3 (highest) | `.opencode/opencode-warden.json` | Project-specific — overrides global |

**Deep merge** means you only need to specify the fields you want to override. Unspecified fields inherit from the layer below.

**Global config** is ideal for settings that apply everywhere — your LLM endpoint, personal PII preferences, custom company patterns.

**Project config** is ideal for project-specific overrides — additional blocked paths, allowlisted files, project-specific tools to monitor.

### Full Configuration Reference

#### Root Options

| Option | Type | Default | Description |
|---|---|---|---|
| `categories` | `Record<PatternCategory, boolean>` | All `true` except `pii-ip-address` | Enable or disable detection categories |
| `disabledPatterns` | `string[]` | `[]` | Pattern IDs to disable (e.g., `["generic-bearer-token"]`) |
| `customPatterns` | `CustomPatternConfig[]` | `[]` | User-defined detection patterns |
| `whitelistedPaths` | `string[]` | `[]` | Glob patterns that bypass file blocking |
| `blockedFilePaths` | `string[]` | See [defaults](#default-blocked-file-paths) | Glob patterns of files to block |
| `excludedTools` | `string[]` | `["glob", "list"]` | Tools to skip entirely (no scanning, no blocking) |
| `sshOnlyMode` | `boolean` | `false` | Only monitor remote commands (ssh, scp, sftp, rsync, rclone) — bypass all local operations |
| `notifications` | `boolean` | `true` | Show toast notifications in the TUI |

#### `audit` — Audit Logging

| Option | Type | Default | Description |
|---|---|---|---|
| `audit.enabled` | `boolean` | `true` | Enable file-based audit logging |
| `audit.filePath` | `string` | `".opencode/security-guard/audit.log"` | Log file path (relative to project root or absolute) |
| `audit.maxFileSize` | `number` | `10485760` (10 MB) | Maximum log file size before rotation |
| `audit.maxFiles` | `number` | `5` | Number of rotated log files to keep |
| `audit.verbosity` | `"quiet" \| "normal" \| "verbose"` | `"normal"` | Logging detail level |

Verbosity levels:
- **`quiet`**: Only blocked attempts
- **`normal`**: Blocks and detections
- **`verbose`**: Everything including clean passes

#### `env` — Environment Sanitization

| Option | Type | Default | Description |
|---|---|---|---|
| `env.enabled` | `boolean` | `true` | Enable environment variable sanitization |
| `env.stripPatterns` | `string[]` | See [defaults](#default-env-strip-patterns) | Env var name patterns to redact (supports `*` wildcard) |

#### `indirectExecution` — Indirect Execution Prevention

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

#### `llm` — LLM Integration

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

#### `llm.safetyEvaluator` — Input Safety Evaluation

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

#### `llm.outputSanitizer` — Output Sanitization

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

#### `customPatterns` — Custom Detection Rules

Each custom pattern entry requires:

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique identifier |
| `name` | `string` | Human-readable name |
| `category` | `PatternCategory` | Category to group under |
| `pattern` | `string` | Regular expression (as string) |
| `redactTemplate` | `string` | Replacement text (e.g., `"[INTERNAL-KEY]"`) |
| `confidence` | `"low" \| "medium" \| "high"` | Detection confidence level |

### Complete Example Configuration

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

  // ── Tool Control ──
  // Tools to skip entirely (no scanning, no blocking)
  "excludedTools": ["glob", "list"],

  // Show toast notifications in the TUI
  "notifications": true,

  // ── Audit Logging ──
  "audit": {
    "enabled": true,
    "filePath": ".opencode/security-guard/audit.log",
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

### Minimal Configurations

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

## How It Works

### Hook Pipeline

Security Guard registers five hooks that intercept the OpenCode tool execution lifecycle:

```
User prompt
    │
    ▼
┌─────────────────────────────────────────────┐
│  permission.ask                             │
│  (if OpenCode's permission system triggers) │
│  → LLM safety eval → set deny/ask/allow    │
│  → mark callID as evaluated                │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  shell.env                                  │
│  (before shell commands)                    │
│  → strip sensitive env var names            │
│  → scan & redact env var values             │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  tool.execute.before                        │
│  → block sensitive file paths               │
│  → deep-scan & redact input args (regex)    │
│  → LLM safety evaluation (if not already    │
│    evaluated by permission.ask)             │
│  → throw Error to block dangerous calls     │
└────────────────────┬────────────────────────┘
                     │
                     ▼
              [ Tool Executes ]
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  tool.execute.after                         │
│  → regex scan & redact output + title       │
│  → LLM sanitization (context-aware pass)    │
│  → audit log & notifications                │
└────────────────────┬────────────────────────┘
                     │
                     ▼
              AI sees clean output
```

Additionally, `experimental.session.compacting` injects security policy context when the session is compacted, ensuring the AI retains awareness of security constraints.

### Detection Engine

The detection engine uses a two-pass approach:

**Pass 1: Regex (fast, deterministic)**
- 74 built-in patterns covering API keys, credentials, private keys, PII, cloud secrets, Docker, and Kubernetes
- Custom user-defined patterns
- Deep recursive scanning of nested objects and arrays (up to 10 levels)
- Overlapping match resolution (longer matches take priority)
- Confidence levels (low, medium, high) for each detection

**Pass 2: LLM (context-aware, catches novel patterns)**
- Optional second pass using a local or remote LLM
- Receives tool name, arguments, and title as context
- Catches secrets that regex misses (e.g., base64-encoded credentials, custom token formats)
- Fails gracefully — if the LLM is unavailable, regex results still apply

### LLM Integration

Security Guard uses any **OpenAI-compatible** chat completions API. This includes:

- [Ollama](https://ollama.ai)
- [llama.cpp](https://github.com/ggerganov/llama.cpp) server
- [vLLM](https://github.com/vllm-project/vllm)
- [LM Studio](https://lmstudio.ai)
- [OpenAI API](https://platform.openai.com)
- [Azure OpenAI](https://azure.microsoft.com/en-us/products/cognitive-services/openai-service)
- Any OpenAI-compatible endpoint

#### Safety Evaluator

The safety evaluator analyzes tool calls across **10 risk dimensions**:

| Dimension | Examples |
|---|---|
| **Exfiltration** | `curl -X POST` with file data, `git push` to unknown remotes |
| **Destruction** | `rm -rf /`, `mkfs`, `DROP DATABASE`, `kubectl delete namespace` |
| **Service Disruption** | `systemctl stop`, `docker kill`, `kill -9` |
| **System Tampering** | Modifying `/etc/passwd`, `/etc/sudoers`, SSH config |
| **Excessive Collection** | `nmap`, `find / -name`, `ps aux`, `getent passwd` |
| **Privilege Escalation** | `sudo`, `chown root`, `chmod 4755`, `setcap` |
| **Persistence** | `crontab -e`, creating systemd services, adding SSH keys |
| **Resource Abuse** | Fork bombs, infinite loops, cryptocurrency miners |
| **Network Manipulation** | `iptables`, DNS configuration, firewall rule changes |
| **Supply Chain** | `curl | bash`, `pip install` from unknown sources |

Each tool call receives a risk level (`none`, `low`, `medium`, `high`, `critical`) and a recommendation (`allow`, `warn`, `block`), determined by configurable thresholds.

#### Context Management

The LLM evaluator maintains a sliding window of conversation history:
- Retains up to 5 user+assistant pairs (configurable)
- Bounded by 16,000 characters (configurable)
- Optionally only keeps exchanges that produced detections
- Resets on new sessions

### Customizing Prompts

Every LLM prompt in OpenCode Warden can be fully replaced via configuration. Set `systemPrompt` to replace the system-level instructions, and `promptTemplate` to replace the user-level prompt format.

| Component | Config path | Template variables |
|---|---|---|
| Safety Evaluator | `llm.safetyEvaluator.systemPrompt` / `promptTemplate` | `{{toolName}}`, `{{args}}` |
| Output Sanitizer | `llm.outputSanitizer.systemPrompt` / `promptTemplate` | `{{toolName}}`, `{{output}}`, `{{context}}` |
| Output Triage | `llm.outputTriage.systemPrompt` / `promptTemplate` | `{{toolName}}`, `{{args}}` |
| Text Triage | `llm.outputTextTriage.systemPrompt` / `promptTemplate` | `{{toolName}}`, `{{args}}`, `{{output}}` |
| Indirect Execution | `indirectExecution.systemPrompt` / `promptTemplate` | `{{command}}`, `{{filePath}}`, `{{fileContent}}`, `{{fileOrigin}}` |

Template variables use `{{variableName}}` syntax and are replaced at runtime. If a field is empty or omitted, the built-in default prompt is used.

**Example** — custom safety evaluator prompt for a CI/CD environment:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "llama3",
    "safetyEvaluator": {
      "systemPrompt": "You are a CI/CD security evaluator. Only block commands that could leak secrets or destroy production data. All build and test commands are safe.",
      "promptTemplate": "Evaluate this CI/CD tool call:\n\nTOOL: {{toolName}}\nARGS:\n{{args}}\n\nRespond with JSON: {\"safe\": true/false, \"riskLevel\": \"none/low/medium/high/critical\", \"riskDimensions\": [], \"explanation\": \"\", \"suggestedAlternative\": \"\", \"recommendation\": \"allow/warn/block\"}"
    }
  }
}
```

### Action Modes

Action modes give you control over how OpenCode Warden responds to threats:

#### Input Safety (`safetyEvaluator.actionMode`)

```
                    ┌──────────────────────────────┐
                    │   Tool call detected as       │
                    │   potentially dangerous        │
                    └──────────┬───────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
         ┌────────┐     ┌────────────┐    ┌────────┐
         │ "block"│     │"permission"│    │ "warn" │
         └───┬────┘     └─────┬──────┘    └───┬────┘
             │                │               │
             ▼                ▼               ▼
        Auto-block      User prompted    Toast warning
        (throw Error)   to allow/deny    (call proceeds)
```

#### Output Sanitization (`outputSanitizer.actionMode`)

```
                    ┌──────────────────────────────┐
                    │   Secret detected in          │
                    │   tool output                 │
                    └──────────┬───────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
        ┌──────────┐    ┌──────────┐     ┌──────────┐
        │ "redact" │    │  "warn"  │     │  "pass"  │
        └────┬─────┘    └────┬─────┘     └────┬─────┘
             │               │                │
             ▼               ▼                ▼
        Auto-redact     Redact + always   No redaction
        (rate-limited   show detailed     (log only,
         toast)         toast             for debugging)
```

### Permission System Integration

When `safetyEvaluator.actionMode` is set to `"permission"`, Security Guard integrates with OpenCode's built-in permission system:

1. **`permission.ask` fires** (when OpenCode prompts the user about a tool call):
   - Security Guard runs its LLM safety evaluation on the tool call
   - If risk is critical/high (at or above `blockThreshold`): auto-denies — the user doesn't see a prompt
   - If risk is medium (at or above `warnThreshold`): sets status to `"ask"` and shows a toast with the risk assessment — the user sees WHY they're being asked and can make an informed decision
   - If safe: leaves the status unchanged — OpenCode's default behavior applies
   - The `callID` is recorded to prevent duplicate evaluation

2. **`tool.execute.before` fires** (always, for every tool call):
   - Checks if this `callID` was already evaluated by `permission.ask` — if so, skips re-evaluation
   - If `permission.ask` didn't fire (tool is auto-allowed in OpenCode config), falls back to `"block"` behavior for safety

This ensures complete coverage: tools that go through OpenCode's permission system get user-prompted decisions with risk context, while auto-allowed tools still get safety evaluation with automatic blocking.

## Built-in Tools

Security Guard provides three tools that the AI (or you) can invoke during a session:

### `security_dashboard`

Displays a real-time security overview:

- Active detection categories and their status
- Session statistics (total calls, detections, blocks)
- Detection breakdown by category
- Blocked file access attempts
- Last 10 security events
- LLM connectivity status

### `security_report`

Generates a comprehensive session report.

**Arguments:**
- `format`: `"summary"` (default) or `"detailed"` (includes full event timeline)

### `security_rules`

Manages custom detection patterns at runtime.

**Arguments:**
- `action`: `"list"`, `"test"`, `"add"`, or `"remove"`
- `pattern`: Regex pattern string (for test/add)
- `testString`: Sample string to test against
- `name`: Rule name (for add)
- `category`: Detection category (for add, defaults to `"api-keys"`)
- `id`: Rule ID (for remove, auto-generated for add)
- `redactTemplate`: Replacement text (for add)

Added rules are persisted to the project's `.opencode/opencode-warden.json` config file.

## Detection Patterns

### API Keys (20 patterns)

| Pattern | Description |
|---|---|
| OpenAI (project) | `sk-proj-*` tokens |
| OpenAI (legacy) | `sk-*` tokens (40+ chars) |
| Anthropic | `sk-ant-*` tokens |
| AWS Access Key | `AKIA*` (20 chars) |
| AWS Secret Key | 40-char base64 strings near AWS context |
| GCP API Key | `AIza*` (39 chars) |
| GitHub PAT | `ghp_*` tokens |
| GitHub OAuth | `gho_*` tokens |
| GitHub Fine-grained | `github_pat_*` tokens |
| Slack | `xox[bpas]-*` tokens |
| Stripe Secret | `sk_live_*` / `sk_test_*` |
| Stripe Restricted | `rk_live_*` / `rk_test_*` |
| JWT | `eyJ*` base64-encoded tokens |
| Bearer Token | Generic `Bearer *` tokens |
| SendGrid | `SG.*` tokens |
| Twilio | `SK*` (32 chars) |
| NPM Token | `npm_*` tokens |
| PyPI Token | `pypi-*` tokens |
| Discord Bot | `Bot *` / long base64 tokens |
| Mailgun | `key-*` tokens |

### Credentials (7 patterns)

| Pattern | Description |
|---|---|
| Password in URL | `://user:password@host` |
| Password Assignment | `password=`, `passwd:`, `api_key:`, etc. |
| MongoDB URI | `mongodb+srv://` connection strings |
| PostgreSQL URI | `postgresql://` / `postgres://` with credentials |
| MySQL URI | `mysql://` connection strings |
| Redis URI | `redis://` connection strings |
| Generic Connection | Connection strings with embedded passwords |

### Private Keys (7 patterns)

RSA, OpenSSH, DSA, EC, generic PEM, encrypted PEM, and PGP private key blocks.

### Docker (4 patterns)

Swarm join tokens, registry auth, inline secrets in `docker run -e`, build arg secrets, and compose environment secrets.

### Kubernetes (6 patterns)

Secret data values, kubeconfig tokens, client key/cert data, Helm `--set` secrets, and service account tokens.

### Cloud Providers (14 patterns)

Azure connection strings, SAS tokens, AD client secrets, Terraform state secrets, variable secrets, HashiCorp Vault tokens, Pulumi config passphrase, Heroku, Vercel, Supabase, Cloudflare, and DigitalOcean tokens.

### PII (6 patterns)

| Pattern | Description |
|---|---|
| Email | Standard email addresses |
| US Phone | US phone number formats |
| International Phone | `+` prefixed numbers |
| SSN | US Social Security Numbers (with separator validation) |
| Credit Card | Major card formats with Luhn checksum validation |
| IP Address | IPv4 addresses (excludes common private ranges like 127.0.0.1, 192.168.*, 10.*) |

> **Note**: `pii-ip-address` is disabled by default due to high false-positive rates. Enable it if your workflow requires IP detection.

## Audit Logging

### Log Format

Audit logs are written as JSON lines (one JSON object per line), enabling easy parsing with standard tools:

```jsonl
{"timestamp":"2026-02-22T14:30:00.000Z","tool":"bash","hook":"before","sessionId":"abc123","callId":"def456","detections":[],"blocked":true,"blockReason":"Safety evaluation: Command attempts to delete system files","redactedCount":0,"safetyEvaluation":{"safe":false,"riskLevel":"critical","riskDimensions":["destruction"],"explanation":"rm -rf / attempts to delete all files","recommendation":"block"}}
{"timestamp":"2026-02-22T14:30:05.000Z","tool":"read","hook":"after","sessionId":"abc123","callId":"ghi789","detections":[{"patternId":"openai-api-key-project","category":"api-keys","confidence":"high"}],"blocked":false,"redactedCount":1}
```

### Log Rotation

When the log file exceeds `maxFileSize` (default 10 MB), it is rotated:

```
audit.log       ← current (active)
audit.log.1     ← previous
audit.log.2     ← older
audit.log.3     ← oldest kept
```

Older files beyond `maxFiles` are automatically deleted.

### Querying Logs

```bash
# Find all blocked attempts
grep '"blocked":true' .opencode/security-guard/audit.log | jq .

# Count detections by category
grep '"hook":"after"' .opencode/security-guard/audit.log | jq '.detections[].category' | sort | uniq -c

# View safety evaluations
grep '"safetyEvaluation"' .opencode/security-guard/audit.log | jq '.safetyEvaluation'
```

## Environment Sanitization

The `shell.env` hook sanitizes environment variables before they reach shell commands. This is a critical defense layer because environment variables often contain secrets that could leak into command outputs or be exfiltrated.

### Two-Strategy Approach

1. **Name-based stripping**: Env vars whose names match patterns like `*_SECRET`, `*_TOKEN`, `AWS_SECRET_ACCESS_KEY`, etc. are replaced with `[REDACTED]`.

2. **Value-based scanning**: All remaining env var values are scanned through the full regex detection engine. Any detected secrets are redacted in-place.

### Default Strip Patterns

```
*_SECRET          *_SECRET_*         *_TOKEN
*_TOKEN_*         *_PASSWORD         *_PASSWORD_*
*_KEY             *_API_KEY          *_API_KEY_*
*_PRIVATE_KEY     DOCKER_AUTH_*      AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN GITHUB_TOKEN       VAULT_TOKEN
PULUMI_CONFIG_PASSPHRASE             HEROKU_API_KEY
VERCEL_TOKEN      CF_API_TOKEN       CF_API_KEY
SUPABASE_SERVICE_ROLE_KEY            DATABASE_URL
REDIS_URL         MONGODB_URI
```

## Example Use Cases

### 1. Solo Developer — Regex-Only Protection

You're a solo developer who wants basic secret protection without running an LLM. No config file needed:

```json
{}
```

What happens:
- 74 regex patterns scan every tool input and output
- `.env`, `*.pem`, `*.key`, and 20+ other sensitive file patterns are blocked
- Environment variables with secret-like names are stripped
- Audit log captures all events
- Toast notifications appear when secrets are detected

### 2. Team Project — Custom Patterns and Blocked Files

Your team has internal API key formats and additional sensitive files:

**`.opencode/opencode-warden.json`:**

```json
{
  "customPatterns": [
    {
      "id": "acme-api-key",
      "name": "ACME Internal API Key",
      "category": "api-keys",
      "pattern": "acme_sk_[A-Za-z0-9]{40}",
      "redactTemplate": "acme_sk_[REDACTED]",
      "confidence": "high"
    }
  ],
  "blockedFilePaths": [
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/secrets/**",
    "**/internal-config.yaml"
  ],
  "whitelistedPaths": [
    "**/.env.example",
    "**/secrets/README.md"
  ]
}
```

### 3. Security-Conscious Workflow — LLM Safety with User Prompts

You want the AI to ask for permission before running risky commands, with a risk assessment shown alongside the prompt:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "llama3",
    "safetyEvaluator": {
      "actionMode": "permission",
      "blockThreshold": "critical",
      "warnThreshold": "low"
    }
  }
}
```

What happens:
- When the AI tries to run `bash` with `rm -rf important_dir/`:
  - LLM evaluates it as `critical` risk → auto-denied, no prompt shown
- When the AI tries to run `bash` with `npm install some-unknown-package`:
  - LLM evaluates it as `medium` risk → OpenCode shows a permission prompt, and a toast shows the risk assessment so you understand WHY you're being asked
- When the AI runs `git status`:
  - Bypassed command → no evaluation, proceeds normally

### 4. CI/CD Auditing Mode — Warn but Don't Block

In a CI/CD environment, you want full visibility without disrupting the pipeline:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://internal-llm:8080/v1",
    "model": "safety-model",
    "safetyEvaluator": {
      "actionMode": "warn"
    },
    "outputSanitizer": {
      "actionMode": "warn"
    }
  },
  "audit": {
    "verbosity": "verbose"
  }
}
```

What happens:
- All tool calls are evaluated for safety risks, but none are blocked
- All output secrets are redacted, with detailed category information in every toast
- Verbose audit logging captures every event including clean passes
- Review the audit log after the run to identify potential issues

### 5. Debugging Secret Detection — Pass Mode

You're testing your custom patterns and want to see what gets detected without any redaction:

```json
{
  "llm": {
    "enabled": false,
    "outputSanitizer": {
      "actionMode": "pass"
    }
  }
}
```

What happens:
- Regex scans still run and detections are logged
- No secrets are redacted in output — you see the raw text
- Toast notifications tell you what was detected and where
- Useful for tuning `disabledPatterns` and `customPatterns`

### 6. Remote Server Administration — SSH-Only Mode

You use OpenCode primarily to administer remote servers and want security monitoring only for remote operations:

```json
{
  "sshOnlyMode": true
}
```

What happens:
- The AI can freely read, edit, and write local files - no scanning or blocking
- When the AI runs `ssh user@server "cat /etc/config"` - the command and output are fully scanned and redacted
- When the AI runs `scp user@server:/home/user/.env ./local/` - blocked (remote `.env` access)
- When the AI runs `rsync -avz user@server:/data/ ./backup/` - remote file paths are checked
- Local commands like `ls`, `git status`, `npm test` bypass all security checks
- Environment variable sanitization is skipped entirely

### 7. Enterprise — Azure OpenAI with Full Lockdown

Corporate environment with Azure OpenAI, strict blocking, and comprehensive auditing:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "https://corp-resource.openai.azure.com/openai/deployments/gpt-4o",
    "model": "gpt-4o",
    "apiKey": "",
    "headers": {
      "api-key": "your-azure-api-key"
    },
    "completionsPath": "/chat/completions?api-version=2024-10-21",
    "healthCheckPath": "/health",
    "safetyEvaluator": {
      "actionMode": "block",
      "blockThreshold": "medium",
      "warnThreshold": "low",
      "tools": ["bash", "write", "edit", "webfetch", "read"]
    },
    "outputSanitizer": {
      "actionMode": "warn",
      "tools": ["read", "bash", "grep", "write", "edit"]
    }
  },
  "categories": {
    "pii-ip-address": true
  },
  "audit": {
    "enabled": true,
    "verbosity": "verbose",
    "maxFileSize": 52428800,
    "maxFiles": 10
  },
  "env": {
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
      "CORP_*",
      "INTERNAL_*"
    ]
  }
}
```

### 8. Global Developer Settings

Settings that apply to all your projects — your LLM endpoint, personal preferences:

**`~/.config/opencode/opencode-warden.json`:**

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "llama3",
    "safetyEvaluator": {
      "actionMode": "permission"
    }
  },
  "categories": {
    "pii-phone": false,
    "pii-ssn": false
  },
  "notifications": true,
  "audit": {
    "verbosity": "normal"
  }
}
```

Then in a specific project that needs stricter settings:

**`.opencode/opencode-warden.json`:**

```json
{
  "llm": {
    "safetyEvaluator": {
      "blockThreshold": "medium"
    }
  },
  "blockedFilePaths": [
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/production-secrets/**"
  ]
}
```

The project config merges into the global config. The project inherits the global LLM endpoint and permission mode, but overrides the block threshold to be more strict.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/toreuyar/opencode-warden).

### Development

```bash
# Install dependencies
bun install

# Run tests
bun test

# Type check
bun run typecheck

# Build
bun run build
```

### Adding Detection Patterns

To add a new built-in pattern:

1. Choose the appropriate file in `src/detection/patterns/`
2. Add a `DetectionPattern` object with:
   - Unique `id`
   - Descriptive `name`
   - Appropriate `category`
   - Precise `pattern` regex (avoid overly broad patterns)
   - `redact` function that replaces matched text
   - `confidence` level (`low`, `medium`, or `high`)
3. Add tests in `tests/patterns.test.ts`
4. Run `bun test` to verify no regressions

## License

MIT License

Copyright (c) 2026 Töre Çağrı Uyar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
