import { describe, test, expect } from "bun:test"
import { buildSecurityPolicyContext } from "../src/hooks/security-policy.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import type { SecurityGuardConfig } from "../src/types.js"

function makeConfig(): SecurityGuardConfig {
  return JSON.parse(JSON.stringify(DEFAULT_CONFIG)) as SecurityGuardConfig
}

describe("buildSecurityPolicyContext", () => {
  test("contains warden header", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("## Warden Security Policy")
  })

  test("contains redaction section", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("### Redaction")
    expect(result).toContain("[REDACTED]")
    expect(result).toContain("Do not reconstruct")
  })

  test("contains blocked files when present", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("### Blocked Files (no read, no write)")
    expect(result).toContain("**/.env")
    expect(result).toContain("**/*.pem")
  })

  test("omits blocked files section when empty", () => {
    const config = makeConfig()
    config.blockedFilePaths = []
    const result = buildSecurityPolicyContext(config)
    expect(result).not.toContain("### Blocked Files")
  })

  test("contains write-protected files section when present", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("### Write-Protected Files (read OK, no write)")
    expect(result).toContain("**/var/log/**")
  })

  test("omits write-protected section when empty", () => {
    const config = makeConfig()
    config.writeProtectedPaths = []
    const result = buildSecurityPolicyContext(config)
    expect(result).not.toContain("### Write-Protected Files")
  })

  test("contains blocked commands warning", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("### Blocked Commands")
    expect(result).toContain("Do NOT retry")
  })

  test("shows output limits when configured", () => {
    const config = makeConfig()
    config.llm.outputSanitizer.maxOutputSize = 65536
    const result = buildSecurityPolicyContext(config)
    expect(result).toContain("### Output Limits")
    expect(result).toContain("65536 characters")
    expect(result).toContain("~64KB")
  })

  test("omits output limits when zero", () => {
    const config = makeConfig()
    config.llm.outputSanitizer.maxOutputSize = 0
    const result = buildSecurityPolicyContext(config)
    expect(result).not.toContain("### Output Limits")
  })

  test("contains security_help pointer", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("security_help")
  })

  test("does NOT contain individual tool descriptions", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).not.toContain("security_dashboard")
    expect(result).not.toContain("security_report")
    expect(result).not.toContain("security_rules")
  })

  test("does NOT contain categories listing", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).not.toContain("Monitored Content Categories")
    expect(result).not.toContain("- api-keys")
  })

  test("does NOT contain allowed operations", () => {
    const config = makeConfig()
    config.llm.safetyEvaluator.operationalProfiles = { "log-review": true }
    const result = buildSecurityPolicyContext(config)
    expect(result).not.toContain("Allowed Operations")
  })

  test("policy is concise (under 60 lines)", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    const lineCount = result.split("\n").length
    expect(lineCount).toBeLessThanOrEqual(60)
  })

  test("default config has no redaction-switch section", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).not.toContain("redactionEnabled")
    expect(result).not.toContain("redactOnWrite")
    expect(result).not.toContain("Exempt Paths")
  })

  test("shows master-disable notice when redactionEnabled is false", () => {
    const config = makeConfig()
    config.redactionEnabled = false
    const result = buildSecurityPolicyContext(config)
    expect(result).toContain("All secret redaction is currently **DISABLED**")
    expect(result).toContain("`redactionEnabled: false`")
    // Should NOT also list the subordinate switches when master is off
    expect(result).not.toContain("Exempt Paths")
    expect(result).not.toContain("`redactOnWrite: false`")
  })

  test("shows write-disable notice when redactOnWrite is false", () => {
    const config = makeConfig()
    config.redactOnWrite = false
    const result = buildSecurityPolicyContext(config)
    expect(result).toContain("`redactOnWrite: false`")
    expect(result).toContain("Redaction on `write`/`edit`/`patch` inputs is **DISABLED**")
  })

  test("lists local exempt paths in the policy", () => {
    const config = makeConfig()
    config.redactionExemptPaths = ["src/config.ts", "**/secrets.example.json"]
    const result = buildSecurityPolicyContext(config)
    expect(result).toContain("Exempt Paths")
    expect(result).toContain("Local (any tool, including bash redirections)")
    expect(result).toContain("`src/config.ts`")
    expect(result).toContain("`**/secrets.example.json`")
  })

  test("lists host-scoped exempt paths grouped by host glob", () => {
    const config = makeConfig()
    config.redactionExemptPaths = [
      "host:web-*:/etc/myapp/**",
      "host:prod-01.example.com:/var/secrets.conf",
    ]
    const result = buildSecurityPolicyContext(config)
    expect(result).toContain("Remote (SSH/SCP/rsync/rclone on matching hosts)")
    expect(result).toContain("On host `web-*`: `/etc/myapp/**`")
    expect(result).toContain("On host `prod-01.example.com`: `/var/secrets.conf`")
  })

  test("omits exempt paths section when list is empty", () => {
    const config = makeConfig()
    config.redactionExemptPaths = []
    const result = buildSecurityPolicyContext(config)
    expect(result).not.toContain("Exempt Paths")
  })

  test("blocks warden config file by default", () => {
    expect(DEFAULT_CONFIG.blockedFilePaths).toContain("**/opencode-warden.json")
  })
})
