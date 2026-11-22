import type { SecurityGuardConfig } from "../types.js"
import { parseExemptEntry } from "../utils/paths.js"

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
    "Warden enforces tool and output security policy.",
  )
  lines.push("")

  // Redaction
  lines.push("### Redaction")
  lines.push(
    "`[REDACTED]` values are permanent. Do not reconstruct, guess, or ask the user to paste redacted content.",
  )
  lines.push("")

  // Dynamic redaction switches + exempt paths — the agent can't read the config
  // file directly (it's blocked), so we inline the values it needs to act on.
  if (!config.redactionEnabled) {
    lines.push("All secret redaction is currently **DISABLED** (`redactionEnabled: false`).")
    lines.push("Access controls and environment sanitization still apply.")
    lines.push("")
  } else {
    if (!config.redactOnWrite) {
      lines.push(
        "Redaction on `write`/`edit`/`patch` inputs is **DISABLED** (`redactOnWrite: false`). Bash command redaction is still active.",
      )
      lines.push("")
    }

    // Split exempt entries into local vs host-scoped for clearer presentation
    const localEntries: string[] = []
    const hostEntries: Array<{ hostGlob: string; pathPattern: string }> = []
    for (const entry of config.redactionExemptPaths) {
      const parsed = parseExemptEntry(entry)
      if (parsed.hostGlob === null) {
        localEntries.push(parsed.pathPattern)
      } else {
        hostEntries.push({ hostGlob: parsed.hostGlob, pathPattern: parsed.pathPattern })
      }
    }

    if (localEntries.length > 0 || hostEntries.length > 0) {
      lines.push("#### Exempt Paths (redaction skipped)")
      lines.push(
        "Read/write redaction is skipped for these paths. Access controls still apply.",
      )
      lines.push("")
      if (localEntries.length > 0) {
        lines.push("Local (any tool, including bash redirections):")
        for (const e of localEntries) lines.push(`- \`${e}\``)
        lines.push("")
      }
      if (hostEntries.length > 0) {
        lines.push("Remote (SSH/SCP/rsync/rclone on matching hosts):")
        for (const e of hostEntries) lines.push(`- On host \`${e.hostGlob}\`: \`${e.pathPattern}\``)
        lines.push("")
      }
    }
  }

  // Blocked file patterns (only if non-empty)
  if (config.blockedFilePaths.length > 0) {
    lines.push("### Blocked Files (no read, no write)")
    lines.push("Secrets and credentials — access fully denied:")
    for (const pattern of config.blockedFilePaths) {
      lines.push(`- \`${pattern}\``)
    }
    lines.push("")
  }

  // Write-protected patterns (only if non-empty)
  if (config.writeProtectedPaths.length > 0) {
    lines.push("### Write-Protected Files (read OK, no write)")
    lines.push("Readable for diagnostics, but never modify or truncate:")
    for (const pattern of config.writeProtectedPaths) {
      lines.push(`- \`${pattern}\``)
    }
    lines.push("")
  }

  // Blocked commands warning
  lines.push("### Blocked Commands")
  lines.push(
    "Do not bypass a safety denial; explain it to the user. When Warden explicitly requests separate or simpler shell calls, retry with dependencies preserved; each revised call still requires all security checks.",
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
