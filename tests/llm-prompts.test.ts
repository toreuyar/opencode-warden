import { describe, test, expect } from "bun:test"
import {
  renderTemplate,
  buildSanitizePrompt,
  buildSafetyPrompt,
  DEFAULT_SANITIZER_PROMPT_TEMPLATE,
  DEFAULT_SAFETY_PROMPT_TEMPLATE,
  DEFAULT_SSH_SAFETY_PROMPT_TEMPLATE,
  DEFAULT_SANITIZER_SYSTEM_PROMPT,
  DEFAULT_SAFETY_SYSTEM_PROMPT,
  SANITIZER_SYSTEM_PROMPT,
  SAFETY_SYSTEM_PROMPT,
} from "../src/llm/prompts.js"

describe("renderTemplate", () => {
  test("replaces single placeholder", () => {
    expect(renderTemplate("Hello {{name}}", { name: "world" })).toBe(
      "Hello world",
    )
  })

  test("replaces multiple placeholders", () => {
    const result = renderTemplate("{{a}} and {{b}}", { a: "X", b: "Y" })
    expect(result).toBe("X and Y")
  })

  test("replaces all occurrences of the same placeholder", () => {
    const result = renderTemplate("{{x}} then {{x}}", { x: "Z" })
    expect(result).toBe("Z then Z")
  })

  test("leaves unmatched placeholders as-is", () => {
    const result = renderTemplate("{{a}} {{b}}", { a: "X" })
    expect(result).toBe("X {{b}}")
  })

  test("handles empty vars", () => {
    const result = renderTemplate("Hello {{name}}", {})
    expect(result).toBe("Hello {{name}}")
  })

  test("handles empty template", () => {
    expect(renderTemplate("", { name: "world" })).toBe("")
  })
})

describe("buildSanitizePrompt", () => {
  test("uses default template when no custom template provided", () => {
    const result = buildSanitizePrompt("bash", "ls output")
    expect(result).toContain("TOOL CONTEXT")
    expect(result).toContain("bash")
    expect(result).toContain("ls output")
    expect(result).toContain("TOOL OUTPUT START")
  })

  test("uses custom template when provided", () => {
    const custom = "Sanitize output from {{toolName}}: {{output}}"
    const result = buildSanitizePrompt("read", "file contents", custom)
    expect(result).toBe("Sanitize output from read: file contents")
  })

  test("falls back to default when custom template is empty string", () => {
    const result = buildSanitizePrompt("bash", "output", "")
    expect(result).toContain("TOOL OUTPUT START")
  })

  test("includes context when provided", () => {
    const context = 'Tool: read\nArguments: {"path":"/app/.env"}\nTitle: Read /app/.env'
    const result = buildSanitizePrompt("read", "SECRET=abc123", undefined, context)
    expect(result).toContain("Tool: read")
    expect(result).toContain("/app/.env")
    expect(result).toContain("SECRET=abc123")
  })

  test("falls back to toolName when context is not provided", () => {
    const result = buildSanitizePrompt("bash", "output")
    expect(result).toContain("bash")
    expect(result).toContain("TOOL CONTEXT")
  })
})

describe("buildSafetyPrompt", () => {
  test("uses default template when no custom template provided", () => {
    const result = buildSafetyPrompt("bash", { command: "rm -rf /" })
    expect(result).toContain("bash")
    expect(result).toContain("rm -rf /")
    expect(result).toContain("Assess the risk")
  })

  test("uses custom template when provided", () => {
    const custom = "Is {{toolName}} safe? Args: {{args}}"
    const result = buildSafetyPrompt("bash", { command: "ls" }, custom)
    expect(result).toContain("Is bash safe?")
    expect(result).toContain('"command": "ls"')
  })

  test("falls back to default when custom template is empty string", () => {
    const result = buildSafetyPrompt("bash", { command: "ls" }, "")
    expect(result).toContain("Assess the risk")
  })
})

describe("backward-compatible aliases", () => {
  test("SANITIZER_SYSTEM_PROMPT equals DEFAULT_SANITIZER_SYSTEM_PROMPT", () => {
    expect(SANITIZER_SYSTEM_PROMPT).toBe(DEFAULT_SANITIZER_SYSTEM_PROMPT)
  })

  test("SAFETY_SYSTEM_PROMPT equals DEFAULT_SAFETY_SYSTEM_PROMPT", () => {
    expect(SAFETY_SYSTEM_PROMPT).toBe(DEFAULT_SAFETY_SYSTEM_PROMPT)
  })
})

describe("default prompt templates", () => {
  test("DEFAULT_SANITIZER_PROMPT_TEMPLATE contains expected placeholders", () => {
    expect(DEFAULT_SANITIZER_PROMPT_TEMPLATE).toContain("{{context}}")
    expect(DEFAULT_SANITIZER_PROMPT_TEMPLATE).toContain("{{output}}")
  })

  test("DEFAULT_SAFETY_PROMPT_TEMPLATE contains expected placeholders", () => {
    expect(DEFAULT_SAFETY_PROMPT_TEMPLATE).toContain("{{toolName}}")
    expect(DEFAULT_SAFETY_PROMPT_TEMPLATE).toContain("{{args}}")
  })

  test("DEFAULT_SSH_SAFETY_PROMPT_TEMPLATE contains SSH placeholders", () => {
    expect(DEFAULT_SSH_SAFETY_PROMPT_TEMPLATE).toContain("{{sshType}}")
    expect(DEFAULT_SSH_SAFETY_PROMPT_TEMPLATE).toContain("{{sshHost}}")
    expect(DEFAULT_SSH_SAFETY_PROMPT_TEMPLATE).toContain("{{sshInnerCommand}}")
    expect(DEFAULT_SSH_SAFETY_PROMPT_TEMPLATE).toContain("{{sshDirection}}")
  })
})

describe("DEFAULT_SAFETY_SYSTEM_PROMPT — DevOps awareness", () => {
  // LOW RISK items (section: "LOW — Read-only (allow):")
  test("contains system monitoring commands in LOW RISK section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("systemctl status")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("df, free, uptime")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("iostat, vmstat")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("ps aux")
  })

  test("contains log reading commands in LOW RISK section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("tail/cat/head on /var/log/*")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("journalctl")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("dmesg")
  })

  test("contains security tool queries in LOW RISK section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("cscli list")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("fail2ban-client status")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("ufw status")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("iptables -L/-S")
  })

  test("contains container inspection commands in LOW RISK section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("docker ps")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("docker compose ps")
  })

  test("contains web server inspection commands in LOW RISK section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("nginx -t/-T")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("apache2ctl -S/-t")
  })

  test("contains network diagnostics in LOW RISK section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("dig, nslookup")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("ping, traceroute, mtr")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("curl HEAD/GET to localhost")
  })

  test("contains certificate inspection in LOW RISK section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("openssl s_client")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("openssl x509")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("certbot certificates")
  })

  test("contains package listing in LOW RISK section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("dpkg -l")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("apt list --installed")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("pip list")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("npm list -g")
  })

  // MEDIUM RISK items (section: "MEDIUM — Reversible maintenance (warn):")
  test("contains service lifecycle in MEDIUM section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("systemctl restart/start/stop/reload/enable/disable")
  })

  test("contains security rule changes in MEDIUM section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("ufw allow/deny specific ports")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("Targeted firewall rules")
  })

  test("contains container lifecycle in MEDIUM section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("docker stop/start/restart")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("docker compose up/down")
  })

  test("contains certificate management in MEDIUM section", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("certbot certonly/renew")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("SSL/TLS config changes")
  })

  // SENSITIVE DATA section (section: "═══ SENSITIVE DATA ═══")
  test("contains SENSITIVE DATA section with key items", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("SENSITIVE DATA")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("terraform.tfstate")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("~/.aws/credentials")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("kubernetes secrets")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("session/auth tokens")
  })

  // Blanket prohibitions removed
  test("does NOT contain blanket sudo prohibition", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).not.toContain("any operation requiring root/sudo")
  })

  test("does NOT contain blanket docker/kubernetes prohibition", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).not.toContain("any docker/kubernetes operation")
  })

  test("does NOT contain blanket /etc /var /usr prohibition", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).not.toContain("any operation on /etc, /var, /usr, /sys, /proc")
  })

  // Nuanced guidance present via inline notes
  test("contains nuanced sudo guidance", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("sudo for routine maintenance is MEDIUM, not escalation")
  })

  test("contains nuanced docker guidance", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("docker ps/inspect/logs/stats/images")
  })

  test("contains nuanced service restart guidance", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("single service restart/stop is MEDIUM (routine)")
  })

  // DevOps context in risk level descriptions
  test("acknowledges DevOps context in risk framework", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("DevOps")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("sudo is expected")
  })
})

describe("buildSafetyPrompt — SSH detection", () => {
  test("SSH command produces SSH context in prompt", () => {
    const result = buildSafetyPrompt("bash", {
      command: 'ssh root@prod.example.com "rm -rf /var/data"',
    })
    expect(result).toContain("SSH CONTEXT")
    expect(result).toContain("Command Type: ssh")
    expect(result).toContain("Target Host: prod.example.com")
    expect(result).toContain("User: root")
    expect(result).toContain("Inner Command: rm -rf /var/data")
    expect(result).toContain("REMOTE OPERATION")
  })

  test("non-SSH bash command uses standard template", () => {
    const result = buildSafetyPrompt("bash", { command: "ls -la" })
    expect(result).not.toContain("SSH CONTEXT")
    expect(result).toContain("Evaluate the safety")
    expect(result).toContain("ls -la")
  })

  test("SCP command produces SSH context with transfer direction", () => {
    const result = buildSafetyPrompt("bash", {
      command: "scp user@server.com:/etc/shadow ./local/",
    })
    expect(result).toContain("SSH CONTEXT")
    expect(result).toContain("Command Type: scp")
    expect(result).toContain("Transfer Direction: download")
    expect(result).toContain("Remote Paths: /etc/shadow")
  })

  test("custom template overrides SSH auto-detection", () => {
    const custom = "Custom: {{toolName}} {{args}}"
    const result = buildSafetyPrompt(
      "bash",
      { command: 'ssh user@host.com "ls"' },
      custom,
    )
    expect(result).not.toContain("SSH CONTEXT")
    expect(result).toContain("Custom: bash")
  })
})
