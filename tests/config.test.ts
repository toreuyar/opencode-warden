import { describe, test, expect } from "bun:test"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import { securityGuardConfigSchema } from "../src/config/schema.js"

describe("Configuration", () => {
  test("default config has all categories", () => {
    const categories = Object.keys(DEFAULT_CONFIG.categories)
    expect(categories).toContain("api-keys")
    expect(categories).toContain("credentials")
    expect(categories).toContain("private-keys")
    expect(categories).toContain("docker")
    expect(categories).toContain("kubernetes")
    expect(categories).toContain("cloud")
    expect(categories).toContain("pii-email")
    expect(categories).toContain("pii-phone")
    expect(categories).toContain("pii-ssn")
    expect(categories).toContain("pii-credit-card")
    expect(categories).toContain("pii-ip-address")
  })

  test("pii-ip-address is disabled by default", () => {
    expect(DEFAULT_CONFIG.categories["pii-ip-address"]).toBe(false)
  })

  test("all other categories are enabled by default", () => {
    for (const [cat, enabled] of Object.entries(DEFAULT_CONFIG.categories)) {
      if (cat === "pii-ip-address") continue
      expect(enabled).toBe(true)
    }
  })

  test("default config has blocked file paths", () => {
    expect(DEFAULT_CONFIG.blockedFilePaths.length).toBeGreaterThan(0)
    expect(DEFAULT_CONFIG.blockedFilePaths).toContain("**/.env")
    expect(DEFAULT_CONFIG.blockedFilePaths).toContain("**/*.pem")
    expect(DEFAULT_CONFIG.blockedFilePaths).toContain("**/.aws/credentials")
    expect(DEFAULT_CONFIG.blockedFilePaths).toContain("**/.docker/config.json")
    expect(DEFAULT_CONFIG.blockedFilePaths).toContain("**/.kube/config")
    expect(DEFAULT_CONFIG.blockedFilePaths).toContain("**/*.tfstate")
  })

  test("default config has env strip patterns", () => {
    expect(DEFAULT_CONFIG.env.stripPatterns.length).toBeGreaterThan(0)
    expect(DEFAULT_CONFIG.env.stripPatterns).toContain("*_SECRET")
    expect(DEFAULT_CONFIG.env.stripPatterns).toContain("*_TOKEN")
    expect(DEFAULT_CONFIG.env.stripPatterns).toContain("AWS_SECRET_ACCESS_KEY")
  })

  test("LLM is disabled by default", () => {
    expect(DEFAULT_CONFIG.llm.enabled).toBe(false)
  })

  test("LLM debug is enabled by default", () => {
    expect(DEFAULT_CONFIG.llm.debug).toBe(true)
  })

  test("Zod schema validates empty config", () => {
    const result = securityGuardConfigSchema.safeParse({})
    expect(result.success).toBe(true)
  })

  test("Zod schema validates partial config", () => {
    const result = securityGuardConfigSchema.safeParse({
      categories: { "pii-ip-address": true },
      disabledPatterns: ["generic-bearer-token"],
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema validates custom patterns", () => {
    const result = securityGuardConfigSchema.safeParse({
      customPatterns: [
        {
          id: "test-key",
          name: "Test Key",
          category: "api-keys",
          pattern: "test_[A-Za-z0-9]{32}",
          redactTemplate: "test_****",
          confidence: "high",
        },
      ],
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema rejects invalid category", () => {
    const result = securityGuardConfigSchema.safeParse({
      categories: { "invalid-category": true },
    })
    expect(result.success).toBe(false)
  })

  test("Zod schema validates LLM config", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: {
        enabled: true,
        baseUrl: "http://localhost:8080/v1",
        model: "llama3",
        temperature: 0.1,
        safetyEvaluator: {
          enabled: true,
          blockThreshold: "high",
          warnThreshold: "medium",
        },
      },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema validates LLM config with debug flag", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: {
        enabled: true,
        debug: true,
        baseUrl: "http://localhost:8080/v1",
        model: "llama3",
      },
    })
    expect(result.success).toBe(true)
  })

  // ─── New LLM configurability fields ───

  test("default config has per-component LLM headers as empty objects", () => {
    expect(DEFAULT_CONFIG.llm.safetyEvaluator.headers).toEqual({})
    expect(DEFAULT_CONFIG.llm.outputSanitizer.headers).toEqual({})
    expect(DEFAULT_CONFIG.llm.outputTriage.headers).toEqual({})
  })

  test("default config has per-component LLM healthCheckPath as empty (fail-closed)", () => {
    expect(DEFAULT_CONFIG.llm.safetyEvaluator.healthCheckPath).toBe("")
    expect(DEFAULT_CONFIG.llm.outputSanitizer.healthCheckPath).toBe("")
    expect(DEFAULT_CONFIG.llm.outputTriage.healthCheckPath).toBe("")
  })

  test("default config has per-component LLM completionsPath as empty (fail-closed)", () => {
    expect(DEFAULT_CONFIG.llm.safetyEvaluator.completionsPath).toBe("")
    expect(DEFAULT_CONFIG.llm.outputSanitizer.completionsPath).toBe("")
    expect(DEFAULT_CONFIG.llm.outputTriage.completionsPath).toBe("")
  })

  test("default config has outputSanitizer.systemPrompt as empty string", () => {
    expect(DEFAULT_CONFIG.llm.outputSanitizer.systemPrompt).toBe("")
  })

  test("default config has outputSanitizer.promptTemplate as empty string", () => {
    expect(DEFAULT_CONFIG.llm.outputSanitizer.promptTemplate).toBe("")
  })

  test("default config has safetyEvaluator.systemPrompt as empty string", () => {
    expect(DEFAULT_CONFIG.llm.safetyEvaluator.systemPrompt).toBe("")
  })

  test("default config has safetyEvaluator.promptTemplate as empty string", () => {
    expect(DEFAULT_CONFIG.llm.safetyEvaluator.promptTemplate).toBe("")
  })

  test("Zod schema validates LLM config with new fields", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: {
        enabled: true,
        baseUrl: "https://my-resource.openai.azure.com/openai/deployments/gpt4",
        model: "gpt-4",
        headers: {
          "api-key": "my-azure-key",
        },
        completionsPath: "/chat/completions?api-version=2024-02-15-preview",
        healthCheckPath: "/health",
        outputSanitizer: {
          systemPrompt: "Custom sanitizer prompt",
          promptTemplate: "Sanitize: {{toolName}} {{output}}",
        },
        safetyEvaluator: {
          systemPrompt: "Custom safety prompt",
          promptTemplate: "Evaluate: {{toolName}} {{args}}",
        },
      },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema ignores unknown fields like maxTokens (removed)", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: {
        outputSanitizer: {
          maxTokens: -1,
        },
      },
    })
    // maxTokens was removed — unknown fields are stripped, not rejected
    expect(result.success).toBe(true)
  })

  // ─── Action Mode fields ───

  test("default config has safetyEvaluator.actionMode as 'block'", () => {
    expect(DEFAULT_CONFIG.llm.safetyEvaluator.actionMode).toBe("block")
  })

  test("default config has outputSanitizer.actionMode as 'redact'", () => {
    expect(DEFAULT_CONFIG.llm.outputSanitizer.actionMode).toBe("redact")
  })

  test("Zod schema validates safetyEvaluator actionMode 'block'", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: { safetyEvaluator: { actionMode: "block" } },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema validates safetyEvaluator actionMode 'permission'", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: { safetyEvaluator: { actionMode: "permission" } },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema validates safetyEvaluator actionMode 'warn'", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: { safetyEvaluator: { actionMode: "warn" } },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema rejects invalid safetyEvaluator actionMode", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: { safetyEvaluator: { actionMode: "invalid" } },
    })
    expect(result.success).toBe(false)
  })

  test("Zod schema validates outputSanitizer actionMode 'redact'", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: { outputSanitizer: { actionMode: "redact" } },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema validates outputSanitizer actionMode 'warn'", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: { outputSanitizer: { actionMode: "warn" } },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema validates outputSanitizer actionMode 'pass'", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: { outputSanitizer: { actionMode: "pass" } },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema rejects invalid outputSanitizer actionMode", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: { outputSanitizer: { actionMode: "invalid" } },
    })
    expect(result.success).toBe(false)
  })

  test("Zod schema validates full config with both action modes", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: {
        enabled: true,
        baseUrl: "http://localhost:8080/v1",
        model: "llama3",
        safetyEvaluator: {
          actionMode: "permission",
          blockThreshold: "high",
        },
        outputSanitizer: {
          actionMode: "warn",
        },
      },
    })
    expect(result.success).toBe(true)
  })

  // ─── Output Sanitizer Bypassed Commands ───

  test("default config has outputSanitizer.bypassedCommands", () => {
    const cmds = DEFAULT_CONFIG.llm.outputSanitizer.bypassedCommands
    expect(cmds.length).toBeGreaterThan(0)
    // Container runtime
    expect(cmds).toContain("docker ps")
    expect(cmds).toContain("podman ps")
    expect(cmds).toContain("crictl ps")
    // Kubernetes & Helm
    expect(cmds).toContain("kubectl top")
    expect(cmds).toContain("helm list")
    // Firewall & network security
    expect(cmds).toContain("ufw status")
    expect(cmds).toContain("iptables -L")
    expect(cmds).toContain("nft list")
    expect(cmds).toContain("firewall-cmd --list-all")
    // CrowdSec
    expect(cmds).toContain("cscli decisions list")
    expect(cmds).toContain("cscli metrics")
    // Fail2ban & SELinux/AppArmor
    expect(cmds).toContain("fail2ban-client status")
    expect(cmds).toContain("sestatus")
    expect(cmds).toContain("aa-status")
    // System info & networking
    expect(cmds).toContain("git status")
    expect(cmds).toContain("ls")
    expect(cmds).toContain("uptime")
    expect(cmds).toContain("ip addr")
    // Build / test
    expect(cmds).toContain("bun test")
    expect(cmds).toContain("cargo test")
    expect(cmds).toContain("pytest")
    // IaC safe subset
    expect(cmds).toContain("terraform validate")
  })

  test("Zod schema validates outputSanitizer bypassedCommands", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: {
        outputSanitizer: {
          bypassedCommands: ["docker ps", "git status"],
        },
      },
    })
    expect(result.success).toBe(true)
  })

  // ─── Operational Profiles & Allowed Operations ───

  test("default config has allowedOperations as empty array", () => {
    expect(DEFAULT_CONFIG.llm.safetyEvaluator.allowedOperations).toEqual([])
  })

  test("default config has operationalProfiles as empty object", () => {
    expect(DEFAULT_CONFIG.llm.safetyEvaluator.operationalProfiles).toEqual({})
  })

  test("Zod schema validates allowedOperations", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: {
        safetyEvaluator: {
          allowedOperations: ["nginx -t", "certbot certificates"],
        },
      },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema validates operationalProfiles with boolean", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: {
        safetyEvaluator: {
          operationalProfiles: {
            "log-review": true,
            "service-status": false,
          },
        },
      },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema validates operationalProfiles with object form", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: {
        safetyEvaluator: {
          operationalProfiles: {
            "security-monitoring": {
              enabled: true,
              additionalPatterns: ["custom-tool status *"],
            },
          },
        },
      },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema rejects operationalProfiles with invalid value", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: {
        safetyEvaluator: {
          operationalProfiles: {
            "log-review": "yes",
          },
        },
      },
    })
    expect(result.success).toBe(false)
  })

  // ─── Diagnostic Log ───

  test("default diagnosticLog.enabled is false", () => {
    expect(DEFAULT_CONFIG.diagnosticLog.enabled).toBe(false)
  })

  test("default diagnosticLog.filePath is correct", () => {
    expect(DEFAULT_CONFIG.diagnosticLog.filePath).toBe(
      ".opencode/warden/diagnostic.log",
    )
  })

  test("default diagnosticLog.maxFileSize is 10MB", () => {
    expect(DEFAULT_CONFIG.diagnosticLog.maxFileSize).toBe(10 * 1024 * 1024)
  })

  test("default diagnosticLog.maxFiles is 3", () => {
    expect(DEFAULT_CONFIG.diagnosticLog.maxFiles).toBe(3)
  })

  test("Zod schema validates diagnosticLog config", () => {
    const result = securityGuardConfigSchema.safeParse({
      diagnosticLog: { enabled: true },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema validates diagnosticLog with custom filePath", () => {
    const result = securityGuardConfigSchema.safeParse({
      diagnosticLog: {
        enabled: true,
        filePath: "/tmp/security-guard.log",
        maxFileSize: 5242880,
        maxFiles: 2,
      },
    })
    expect(result.success).toBe(true)
  })

  test("Zod schema rejects negative diagnosticLog.maxFileSize", () => {
    const result = securityGuardConfigSchema.safeParse({
      diagnosticLog: { maxFileSize: -1 },
    })
    expect(result.success).toBe(false)
  })

  test("Zod schema rejects non-integer diagnosticLog.maxFiles", () => {
    const result = securityGuardConfigSchema.safeParse({
      diagnosticLog: { maxFiles: 1.5 },
    })
    expect(result.success).toBe(false)
  })

  test("Zod schema validates full config with operational profiles", () => {
    const result = securityGuardConfigSchema.safeParse({
      llm: {
        enabled: true,
        baseUrl: "http://localhost:8080/v1",
        model: "llama3",
        safetyEvaluator: {
          enabled: true,
          allowedOperations: ["nginx -t"],
          operationalProfiles: {
            "log-review": true,
            "security-monitoring": {
              enabled: true,
              additionalPatterns: ["custom-sec-tool *"],
            },
            "service-status": true,
            "system-health": false,
          },
        },
      },
    })
    expect(result.success).toBe(true)
  })
})
