import type { SecurityGuardConfig } from "../types.js"

/**
 * Build the security policy context text that explains the monitoring system
 * to the main LLM. Used both at session start and during compaction.
 *
 * This is intentionally minimal — detailed tool documentation lives in
 * the `security_help` tool (three-tier context strategy).
 */
export function buildSecurityPolicyContext(config: SecurityGuardConfig): string {
  const lines: string[] = []

  lines.push("## Warden Security Policy")
  lines.push("")
  lines.push(
    "A security monitoring system is active. All tool calls and outputs are inspected.",
  )
  lines.push("")

  // Redaction
  lines.push("### Redaction")
  lines.push(
    "`[REDACTED]` values are permanent. Do not reconstruct, guess, or ask the user to paste redacted content.",
  )
  lines.push("")

  // Blocked file patterns (only if non-empty)
  if (config.blockedFilePaths.length > 0) {
    lines.push("### Blocked Files")
    for (const pattern of config.blockedFilePaths) {
      lines.push(`- \`${pattern}\``)
    }
    lines.push("")
  }

  // Blocked commands warning
  lines.push("### Blocked Commands")
  lines.push(
    "Commands blocked by the safety evaluator cannot be bypassed. Do NOT retry with variations — explain the situation to the user instead.",
  )
  lines.push("")

  // Output size limit (conditional)
  const maxOutputSize = config.llm.outputSanitizer.maxOutputSize
  if (maxOutputSize > 0) {
    lines.push("### Output Limits")
    lines.push(
      `Output limited to ${maxOutputSize} characters (~${Math.round(maxOutputSize / 1024)}KB). Use targeted commands (head, tail, grep).`,
    )
    lines.push("")
  }

  // Pointer to help tool
  lines.push(
    "Use `security_help` for available security tools and capabilities.",
  )

  return lines.join("\n")
}
