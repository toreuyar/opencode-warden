# Audit Logging & Environment Sanitization

[← Back to README](../README.md)

## Audit Logging

### Log Format

Audit logs are written as JSON lines (one JSON object per line), enabling easy parsing with standard tools:

```jsonl
{"timestamp":"2026-02-22T14:30:00.000Z","tool":"bash","hook":"before","sessionId":"abc123","callId":"def456","detections":[],"blocked":true,"blockReason":"Safety evaluation: Command attempts to delete system files","redactedCount":0,"safetyEvaluation":{"safe":false,"riskLevel":"critical","riskDimensions":["destruction"],"explanation":"rm -rf / attempts to delete all files","recommendation":"block"}}
{"timestamp":"2026-02-22T14:30:05.000Z","tool":"read","hook":"after","sessionId":"abc123","callId":"ghi789","detections":[{"patternId":"openai-api-key-project","category":"api-keys","confidence":"high"}],"blocked":false,"redactedCount":1}
```

### Log Location

By default, logs are written to `.opencode/warden/audit.log` relative to the project root. This can be changed with `audit.filePath` in your config.

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

These patterns support `*` as a wildcard. Add your own patterns via `env.stripPatterns` in config. When `sshOnlyMode` is enabled, environment sanitization is skipped entirely (since local operations are not monitored).
