# Built-in Tools

[← Back to README](../README.md)

Warden provides 7 built-in tools that the AI (or you) can invoke during a session. These tools give you and the AI real-time visibility into security state, session history, audit records, and rule management — without leaving your workflow.

## `security_help`

Parametric tool discovery — lists available Warden tools and their arguments.

Useful when the AI needs to know what security tools are available and how to call them. Returns a structured list of all tools with their argument schemas and descriptions.

## `security_dashboard`

Displays a real-time security overview of the current session.

**Arguments:**
- `mode`: `"full"` (default) or `"brief"`

**Full mode shows:**
- Active detection categories and their status
- Session statistics (total calls, detections, blocks)
- Detection breakdown by category
- Blocked file access attempts
- Last 10 security events
- LLM connectivity status

**Brief mode shows:**
- A compact summary: total calls, detections, blocks, and top triggered category
- Suitable for quick status checks mid-session

## `security_report`

Generates a comprehensive session security report.

**Arguments:**
- `format`: `"summary"` (default) or `"detailed"`

**Summary format** includes:
- Session duration and total tool calls
- Detection counts by category
- Block count and reasons
- LLM evaluation statistics (if LLM is enabled)

**Detailed format** includes everything in summary, plus:
- Full chronological event timeline
- Per-event tool name, hook, detections, and block reasons
- Useful for post-session review or audit export

## `security_audit`

Queries the audit log file with optional filters, returning matching entries.

**Arguments:**
- `limit`: Maximum number of entries to return (default: 50)
- `tool`: Filter by tool name (e.g., `"bash"`, `"read"`)
- `blocked`: `true` to return only blocked calls, `false` for non-blocked, omit for all
- `since`: ISO 8601 timestamp — only return entries after this time
- `category`: Filter by detection category (e.g., `"api-keys"`, `"credentials"`)

Returns parsed JSON log entries from `.opencode/warden/audit.log`. Useful for the AI to investigate past security events without requiring external tools.

## `security_evaluate`

Dry-run safety evaluation — evaluates a hypothetical tool call without executing it.

**Arguments:**
- `toolName`: The tool to evaluate (e.g., `"bash"`, `"write"`)
- `args`: The arguments object as it would be passed to the tool

Returns the LLM safety evaluation result: risk level, risk dimensions, explanation, and recommendation. Does not execute the tool or log to the audit trail.

Useful for the AI to pre-check whether a command it is considering would be blocked, so it can adjust its approach before attempting execution.

## `security_config`

Read-only view of the active Warden configuration. Secrets and API keys are masked in the output.

**Arguments:**
- `section`: Optional — show only a specific section (e.g., `"llm"`, `"audit"`, `"env"`, `"blockedFilePaths"`)

Returns the merged effective configuration (global + project layers combined) with sensitive values replaced by `[MASKED]`. Useful for diagnosing why a pattern is or isn't triggering, or verifying which config layer is active.

## `security_rules`

Manages custom detection patterns at runtime using a three-layer architecture.

**Arguments:**
- `action`: `"list"`, `"test"`, `"add"`, or `"remove"`
- `pattern`: Regex pattern string (for `test` / `add`)
- `testString`: Sample string to test against (for `test`)
- `name`: Rule name (for `add`)
- `category`: Detection category (for `add`, defaults to `"api-keys"`)
- `id`: Rule ID (for `remove`; auto-generated for `add`)
- `redactTemplate`: Replacement text (for `add`)
- `layer`: Rule layer for `list` — `"builtin"`, `"user"`, or `"ai"` (omit for all)

### Three-Layer Rule Architecture

Rules are organized into three layers with different persistence and management semantics:

| Layer | Who manages it | Where stored | Persisted |
|---|---|---|---|
| `builtin` | Warden itself | Compiled into the plugin | No (read-only) |
| `user` | You (human) | `.opencode/opencode-warden.json` `customPatterns` | Yes |
| `ai` | The AI agent | `.opencode/warden/ai-rules.json` | Yes |

- **`list`** — show all rules (optionally filtered by layer)
- **`test`** — test a regex pattern against a sample string to verify it works before adding
- **`add`** — add a new rule; the AI agent's rules go into the `ai` layer, user rules to the `user` layer
- **`remove`** — remove a rule by ID from the `user` or `ai` layer (builtin rules cannot be removed, only disabled via `disabledPatterns` in config)

Rules added via `add` take effect immediately for the current session and are persisted for future sessions.
