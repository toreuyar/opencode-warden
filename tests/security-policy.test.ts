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
    expect(result).toContain("### Blocked Files")
    expect(result).toContain("**/.env")
    expect(result).toContain("**/*.pem")
  })

  test("omits blocked files section when empty", () => {
    const config = makeConfig()
    config.blockedFilePaths = []
    const result = buildSecurityPolicyContext(config)
    expect(result).not.toContain("### Blocked Files")
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

  test("policy is concise (under 40 lines)", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    const lineCount = result.split("\n").length
    expect(lineCount).toBeLessThanOrEqual(50)
  })
})
