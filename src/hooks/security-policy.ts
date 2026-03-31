import type { SecurityGuardConfig, PatternCategory } from "../types.js"
import { getActiveProfileDescriptions } from "../config/profiles.js"

/**
 * Build the security policy context text that explains the monitoring system
 * to the main LLM. Used both at session start and during compaction.
 */
export function buildSecurityPolicyContext(config: SecurityGuardConfig): string {
  const lines: string[] = []

  lines.push("## Security Guard Policy")
  lines.push("")
  lines.push(
    "A security monitoring system is active on this workspace. All tool inputs and outputs are inspected by the system before they reach you. The following rules apply:",
  )
  lines.push("")

  // Redaction notice
  lines.push("### Content Redaction")
  lines.push(
    "When you see `[REDACTED]` in any tool output (file contents, command results, etc.), it means the security system has replaced sensitive content before delivering the output to you. This is automatic and not an error.",
  )
  lines.push("")
  lines.push(
    "- `[REDACTED]` values are **permanent** — the original content is not available to you.",
  )
  lines.push(
    "- **Do not** attempt to reconstruct, guess, or infer what was redacted.",
  )
  lines.push(
    "- **Do not** ask the user to paste redacted values in plain text.",
  )
  lines.push(
    "- If a tool output contains `[REDACTED]`, work around it — the rest of the output is still usable.",
  )
  lines.push("")

  // Blocked file patterns
  if (config.blockedFilePaths.length > 0) {
    lines.push("### Blocked File Paths")
    lines.push(
      "The following files are blocked by the security system. Attempts to read or access them will be rejected:",
    )
    for (const pattern of config.blockedFilePaths) {
      lines.push(`- \`${pattern}\``)
    }
    lines.push("")
    lines.push(
      "Blocked files cannot be accessed. Work around this by using alternative paths or different approaches. You may inform the user after completing the operation with an alternative.",
    )
    lines.push("")
  }

  // Active detection categories
  const activeCategories = (
    Object.entries(config.categories) as [PatternCategory, boolean][]
  )
    .filter(([, enabled]) => enabled)
    .map(([cat]) => cat)

  if (activeCategories.length > 0) {
    lines.push("### Monitored Content Categories")
    lines.push(
      "The security system monitors for and redacts the following types of sensitive data:",
    )
    for (const cat of activeCategories) {
      lines.push(`- ${cat}`)
    }
    lines.push("")
  }

  // Allowed operations
  const safetyEval = config.llm.safetyEvaluator
  const activeProfiles = getActiveProfileDescriptions(
    safetyEval.operationalProfiles,
  )

  if (activeProfiles.length > 0 || safetyEval.allowedOperations.length > 0) {
    lines.push("### Allowed Operations")
    lines.push(
      "The following operations are pre-approved and bypass LLM safety evaluation:",
    )
    lines.push("")

    if (activeProfiles.length > 0) {
      lines.push("**Active Profiles:**")
      for (const { name, description } of activeProfiles) {
        lines.push(`- \`${name}\`: ${description}`)
      }
      lines.push("")
    }

    if (safetyEval.allowedOperations.length > 0) {
      lines.push("**Custom Patterns:**")
      for (const pattern of safetyEval.allowedOperations) {
        lines.push(`- \`${pattern}\``)
      }
      lines.push("")
    }
  }

  // Output size limit
  const maxOutputSize = config.llm.outputSanitizer.maxOutputSize
  if (maxOutputSize > 0) {
    lines.push("### Output Size Limit")
    lines.push(
      `Tool output is limited to **${maxOutputSize} characters** (~${Math.round(maxOutputSize / 1024)}KB). Output exceeding this limit will be blocked and you will not receive the content.`,
    )
    lines.push("")
    lines.push(
      "To stay within the limit, always use targeted commands:",
    )
    lines.push("- `head -n 50` or `tail -n 50` instead of `cat`")
    lines.push("- `grep` to filter for relevant lines")
    lines.push("- `wc -l` to count lines before reading")
    lines.push("- `| head`, `| tail`, `| grep` to pipe and filter large output")
    lines.push("- Read specific line ranges instead of entire files")
    lines.push("")
  }

  // Tool call monitoring
  lines.push("### Tool Call Monitoring")
  lines.push(
    "All tool calls (bash commands, file writes, file edits, web requests) are evaluated by the security system before execution. Commands deemed dangerous will be blocked. Do NOT retry blocked commands with minor variations or alternative syntax — this will not bypass the security system and will waste cycles. Instead, explain the situation to the user and ask them to perform the action manually or confirm it is safe.",
  )
  lines.push("")

  // Available tools
  lines.push("### Security Tools")
  lines.push(
    "- `security_dashboard` — Check current security status and statistics.",
  )
  lines.push(
    "- `security_report` — Generate a detailed security report for the session.",
  )
  lines.push(
    "- `security_rules` — Manage custom detection rules (list/test/add/remove).",
  )

  return lines.join("\n")
}
