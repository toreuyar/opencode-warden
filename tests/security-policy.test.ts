import { describe, test, expect } from "bun:test"
import { buildSecurityPolicyContext } from "../src/hooks/security-policy.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import type { SecurityGuardConfig } from "../src/types.js"

function makeConfig(): SecurityGuardConfig {
  return JSON.parse(JSON.stringify(DEFAULT_CONFIG)) as SecurityGuardConfig
}

describe("buildSecurityPolicyContext", () => {
  test("contains security guard header", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("## Security Guard Policy")
  })

  test("contains content redaction section", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("### Content Redaction")
    expect(result).toContain("[REDACTED]")
    expect(result).toContain("Do not")
  })

  test("contains blocked file paths when present", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("### Blocked File Paths")
    expect(result).toContain("**/.env")
    expect(result).toContain("**/*.pem")
  })

  test("omits blocked file paths section when empty", () => {
    const config = makeConfig()
    config.blockedFilePaths = []
    const result = buildSecurityPolicyContext(config)
    expect(result).not.toContain("### Blocked File Paths")
  })

  test("lists active detection categories", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("### Monitored Content Categories")
    expect(result).toContain("api-keys")
    expect(result).toContain("credentials")
    expect(result).toContain("private-keys")
  })

  test("does not list disabled categories", () => {
    const config = makeConfig()
    // pii-ip-address is disabled by default
    const result = buildSecurityPolicyContext(config)
    expect(result).not.toContain("- pii-ip-address")
  })

  test("contains tool call monitoring section", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("### Tool Call Monitoring")
    expect(result).toContain("blocked")
  })

  test("contains security tools section", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).toContain("### Security Tools")
    expect(result).toContain("security_dashboard")
    expect(result).toContain("security_report")
    expect(result).toContain("security_rules")
  })

  test("shows output size limit when configured", () => {
    const config = makeConfig()
    config.llm.outputSanitizer.maxOutputSize = 65536
    const result = buildSecurityPolicyContext(config)
    expect(result).toContain("### Output Size Limit")
    expect(result).toContain("65536 characters")
    expect(result).toContain("~64KB")
  })

  test("omits output size limit when zero", () => {
    const config = makeConfig()
    config.llm.outputSanitizer.maxOutputSize = 0
    const result = buildSecurityPolicyContext(config)
    expect(result).not.toContain("### Output Size Limit")
  })

  test("shows allowed operations when profiles are active", () => {
    const config = makeConfig()
    config.llm.safetyEvaluator.operationalProfiles = {
      "log-review": true,
      "service-status": true,
    }
    const result = buildSecurityPolicyContext(config)
    expect(result).toContain("### Allowed Operations")
    expect(result).toContain("Active Profiles")
    expect(result).toContain("log-review")
    expect(result).toContain("service-status")
  })

  test("shows custom allowed operations", () => {
    const config = makeConfig()
    config.llm.safetyEvaluator.allowedOperations = ["nginx -t", "certbot certificates"]
    const result = buildSecurityPolicyContext(config)
    expect(result).toContain("### Allowed Operations")
    expect(result).toContain("Custom Patterns")
    expect(result).toContain("nginx -t")
    expect(result).toContain("certbot certificates")
  })

  test("omits allowed operations when none configured", () => {
    const result = buildSecurityPolicyContext(DEFAULT_CONFIG)
    expect(result).not.toContain("### Allowed Operations")
  })
})
