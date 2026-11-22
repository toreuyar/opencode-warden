# Audit Logging & Environment Sanitization

[← Back to README](../README.md)

## Audit Logging

### Provider scheduling diagnostics (2.2.0)

With diagnostic logging enabled, scheduling records correlate generated
request/call/attempt IDs with queue admission, active capacity, and retry timing.
Queue metrics contain no prompts, endpoint credentials, or raw tool arguments.
The full `security_dashboard` also shows process-wide queue state.

The separate LLM chat log intentionally records conversation content. Each HTTP
attempt now owns its streaming counters and tags every fragment with request
and attempt IDs, so overlapping requests remain distinguishable. Chat-log
failure remains non-critical and cannot change enforcement.

### Log Format

Audit logs are written as JSON lines (one JSON object per line), enabling easy parsing with standard tools:

```jsonl
{"timestamp":"2026-02-22T14:30:00.000Z","tool":"shell","hook":"before","sessionId":"abc123","callId":"def456","detections":[],"blocked":true,"blockReason":"Safety evaluation: Command attempts to delete system files","redactedCount":0,"safetyEvaluation":{"safe":false,"riskLevel":"critical","riskDimensions":["destruction"],"explanation":"rm -rf / attempts to delete all files","recommendation":"block"}}
{"timestamp":"2026-02-22T14:30:05.000Z","tool":"read","hook":"after","sessionId":"abc123","callId":"ghi789","detections":[{"patternId":"openai-api-key","category":"api-keys","confidence":"high"}],"blocked":false,"redactedCount":1}
```

Audit entries use `hook` values for each interception point, including
`before`, `after`, `permission`, `context`, `generate`, `title`, `shell`, `env`,
`compaction`, and the retained `chat.message` label for prompt scanning. V2 tool
names are canonical (`shell`, `subagent`); legacy entries remain readable by tool
name.

### Log Location

By default, logs are written to `.opencode/warden/audit.log` relative to the project root. This can be changed with `audit.filePath` in your config.

Writes are buffered and flushed after 1 second or 10 entries. A short-lived
`opencode run --standalone` process that exits immediately can therefore leave a
0-byte audit file even though a block was enforced; a long-lived server flushes
normally. This is a durability gap, not an enforcement bypass. When the audit
record must be retained, use a server session rather than a one-shot CLI run.

### Log Rotation

When the log file exceeds `maxFileSize` (default 10 MB), it is rotated:

```
audit.log       ← current (active)
audit.log.1     ← previous
audit.log.2     ← older
audit.log.3     ← oldest kept
```

Older files beyond `maxFiles` are automatically deleted.

### Verbosity Levels

Control how much is written to the log with `audit.verbosity`:

- **`quiet`**: Only blocked attempts
- **`normal`**: Blocks and detections (default)
- **`verbose`**: Everything including clean passes

### Querying Logs

```bash
# Find all blocked attempts
grep '"blocked":true' .opencode/warden/audit.log | jq .

# Count detections by category
grep '"hook":"after"' .opencode/warden/audit.log | jq '.detections[].category' | sort | uniq -c

# View safety evaluations
grep '"safetyEvaluation"' .opencode/warden/audit.log | jq '.safetyEvaluation'
```

You can also use the [`security_audit`](tools.md#security_audit) built-in tool to query the log from within your OpenCode session without leaving the AI workflow.

### Diagnostic Log

The audit log and diagnostic log are independent. Enable the diagnostic log in
config (`diagnosticLog.enabled`) to record hook start/end, decisions, and LLM
chat traffic. When enabled, a separate `*-llm.log` file in the same directory
records model requests and responses. Diagnostics are sanitized and never
include configured secret values. The audit log remains the primary durable
security record.

### Notifications Are Not Audit Records

TUI/RPC notifications are UX-only. They contain a closed event kind and bounded
metadata (an optional canonical tool id and count), never paths, arguments,
output, explanations, or raw audit text. If the TUI/RPC bridge is unavailable,
alerts are absent but enforcement and audit logging continue. Do not use
notifications as an audit trail; query `.opencode/warden/audit.log`.

## Environment Sanitization and the Shell Backstop

The `shell.create.before` hook (the V2 replacement for `shell.env`) first runs a
deterministic path backstop and then sanitizes environment variables before they
reach shell commands. This is a critical defense layer because environment
variables often contain secrets that could leak into command outputs or be
exfiltrated.

The backstop applies to **every shell creation**, including the user's own
terminals and background shells, not only agent tool calls. Blocked and
write-protected paths are therefore also unreachable through a user terminal.
Relative `cwd` values are resolved against the workspace, and
SSH/SCP/rsync/rclone remote paths are checked. Dynamic targets that require
shell expansion (for example unexpanded `$VAR` or backticks) are skipped because
resolving them would require executing the shell. This deterministic limitation
is intentional.

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

These patterns support `*` as a wildcard. Add your own patterns via `env.stripPatterns` in config. When `sshOnlyMode` is enabled, environment sanitization is skipped entirely (since local operations are not monitored).
