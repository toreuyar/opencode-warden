# How It Works

[← Back to README](../README.md)

## Hook Pipeline

Warden registers five hooks that intercept the OpenCode tool execution lifecycle:

```
User prompt
    │
    ▼
┌─────────────────────────────────────────────┐
│  permission.ask                             │
│  (if OpenCode's permission system triggers) │
│  → LLM safety eval → set deny/ask/allow     │
│  → mark callID as evaluated                 │
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

## Detection Engine

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

## LLM Integration

Warden uses any **OpenAI-compatible** chat completions API. This includes:

- [Ollama](https://ollama.ai)
- [llama.cpp](https://github.com/ggerganov/llama.cpp) server
- [vLLM](https://github.com/vllm-project/vllm)
- [LM Studio](https://lmstudio.ai)
- [OpenAI API](https://platform.openai.com)
- [Azure OpenAI](https://azure.microsoft.com/en-us/products/cognitive-services/openai-service)
- Any OpenAI-compatible endpoint

### Safety Evaluator

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

### Context Management

The LLM evaluator maintains a sliding window of conversation history:
- Retains up to 5 user+assistant pairs (configurable)
- Bounded by 16,000 characters (configurable)
- Optionally only keeps exchanges that produced detections
- Resets on new sessions

## Customizing Prompts

Every LLM prompt in Warden can be fully replaced via configuration. Set `systemPrompt` to replace the system-level instructions, and `promptTemplate` to replace the user-level prompt format.

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

## Action Modes

Action modes give you control over how Warden responds to threats:

### Input Safety (`safetyEvaluator.actionMode`)

```
                ┌──────────────────────────────┐
                │   Tool call detected as      │
                │   potentially dangerous      │
                └──────────────┬───────────────┘
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

### Output Sanitization (`outputSanitizer.actionMode`)

```
                ┌─────────────────────────────┐
                │   Secret detected in        │
                │   tool output               │
                └─────────────┬───────────────┘
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
        ┌──────────┐    ┌──────────┐     ┌──────────┐
        │ "redact" │    │  "warn"  │     │  "pass"  │
        └────┬─────┘    └────┬─────┘     └────┬─────┘
             │               │                │
             ▼               ▼                ▼
        Auto-redact     Redact + always   No redaction
        (rate-limited   show detailed     (log only,
         toast)         toast             for debugging)
```

## Permission System Integration

When `safetyEvaluator.actionMode` is set to `"permission"`, Warden integrates with OpenCode's built-in permission system:

1. **`permission.ask` fires** (when OpenCode prompts the user about a tool call):
   - Warden runs its LLM safety evaluation on the tool call
   - If risk is critical/high (at or above `blockThreshold`): auto-denies — the user doesn't see a prompt
   - If risk is medium (at or above `warnThreshold`): sets status to `"ask"` and shows a toast with the risk assessment — the user sees WHY they're being asked and can make an informed decision
   - If safe: leaves the status unchanged — OpenCode's default behavior applies
   - The `callID` is recorded to prevent duplicate evaluation

2. **`tool.execute.before` fires** (always, for every tool call):
   - Checks if this `callID` was already evaluated by `permission.ask` — if so, skips re-evaluation
   - If `permission.ask` didn't fire (tool is auto-allowed in OpenCode config), falls back to `"block"` behavior for safety

This ensures complete coverage: tools that go through OpenCode's permission system get user-prompted decisions with risk context, while auto-allowed tools still get safety evaluation with automatic blocking.
