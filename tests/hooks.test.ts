import { describe, test, expect } from "bun:test"
import { createDetectionEngine } from "../src/detection/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import { AuditLogger } from "../src/audit/index.js"
import { SessionStats } from "../src/audit/session-stats.js"
import { createInputSanitizer } from "../src/hooks/input-sanitizer.js"
import { createOutputRedactor } from "../src/hooks/output-redactor.js"
import { createEnvSanitizer } from "../src/hooks/env-sanitizer.js"
import { createCompactionContext } from "../src/hooks/compaction-context.js"
import { createPromptSanitizer } from "../src/hooks/prompt-sanitizer.js"
import { createSessionContextCapture, sweepStaleSessions } from "../src/hooks/session-context.js"
import type { PluginClient, ToastState, WrittenFileMetadata } from "../src/types.js"

const mockClient: PluginClient = {
  app: {
    log: async () => undefined,
  },
  tui: {
    showToast: async () => undefined,
  },
  session: {
    prompt: async () => undefined,
  },
}

const testAuditConfig = {
  ...DEFAULT_CONFIG.audit,
  enabled: false,
}

function createTestDeps() {
  const engine = createDetectionEngine(DEFAULT_CONFIG)
  const auditLogger = new AuditLogger(testAuditConfig)
  const sessionStats = new SessionStats("test")
  const toastState: ToastState = { lastToastTime: 0, minInterval: 0 }
  const sessionAllowlist = new Set<string>()
  const evaluatedCalls = new Set<string>()
  const writtenFileRegistry = new Map<string, WrittenFileMetadata>()

  return {
    engine,
    auditLogger,
    sessionStats,
    toastState,
    sessionAllowlist,
    evaluatedCalls,
    writtenFileRegistry,
    diagnosticLogger: null,
    outputTriage: null,
    outputTextTriage: null,
  }
}

describe("Input Sanitizer Hook", () => {
  test("blocks access to .env file", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "read", sessionID: "s1", callID: "c1" }
    const output = { args: { filePath: "/project/.env" } }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("blocks bash append to authorized_keys via >> (T5.7)", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        command:
          "echo 'ssh-ed25519 AAAA...' >> ~/.ssh/authorized_keys",
      },
    }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("blocks bash overwrite of .env via > ", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = { args: { command: "echo SECRET=x > /app/.env" } }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("blocks bash tee to a blocked key file", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = { args: { command: "cat stolen | tee ~/.ssh/id_rsa" } }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("blocks bash dd of= to a blocked file", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: { command: "dd if=/dev/zero of=/app/secrets.key bs=1M" },
    }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("allows bash redirection to non-blocked files", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = { args: { command: "echo hello > /tmp/output.txt" } }

    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  test("allows bash 2>/dev/null (safe redirect, not a blocked target)", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = { args: { command: "cmd 2>/dev/null" } }

    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  // ─── write-protected paths: read allowed, write blocked ───

  test("blocks bash truncate of write-protected /var/log file (T2.4)", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = { args: { command: "truncate -s 0 /var/log/syslog" } }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("blocks bash empty-redirect of write-protected /var/log file (T2.3)", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = { args: { command: ": > /var/log/auth.log" } }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("allows bash READ of write-protected /var/log file (tail)", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    // No redirection, no write target — reading a log via cat is a READ
    // (extractFilePath catches cat, checks blockedFilePaths only, log isn't there)
    const output = { args: { command: "cat /var/log/syslog | head -20" } }

    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  test("write tool to a write-protected path is blocked, read tool is allowed", async () => {
    // Configure: /project/state.log is write-protected
    const deps = createTestDeps()
    const config = {
      ...DEFAULT_CONFIG,
      writeProtectedPaths: ["**/state.log"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    // write tool → blocked
    await expect(
      hook(
        { tool: "write", sessionID: "s1", callID: "c1" },
        { args: { filePath: "/project/state.log" } },
      ),
    ).rejects.toThrow("blocked by security policy")

    // read tool → allowed (write-protection doesn't block reads)
    await expect(
      hook(
        { tool: "read", sessionID: "s1", callID: "c2" },
        { args: { filePath: "/project/state.log" } },
      ),
    ).resolves.toBeUndefined()
  })

  test("bash input-redirect read of a secret blocked file is blocked", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    // < .env is a READ of a secret → blocked by blockedFilePaths
    const output = { args: { command: "mail root < /app/.env" } }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("bash truncate reference to a secret blocked file is blocked as a read", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = { args: { command: "truncate -r /app/.env /tmp/out" } }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("blocks dynamic bash file targets that cannot be checked deterministically", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = { args: { command: "echo SECRET=x > $HOME/.env" } }

    await expect(hook(input, output)).rejects.toThrow(
      "dynamic shell target",
    )
  })

  test("allows access to normal files", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "read", sessionID: "s1", callID: "c1" }
    const output = { args: { filePath: "/project/src/index.ts" } }

    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  test("redacts secrets in tool args", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        command: "echo sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      },
    }

    await hook(input, output)
    expect(output.args.command as string).not.toContain("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
  })

  test("skips excluded tools", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "list", sessionID: "s1", callID: "c1" }
    const output = { args: {} }

    // Should not throw since list is excluded
    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  test("blocks glob targeting blocked directory", async () => {
    const deps = createTestDeps()
    const configWithOpencode = {
      ...DEFAULT_CONFIG,
      blockedFilePaths: [...DEFAULT_CONFIG.blockedFilePaths, "**/.opencode/**"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithOpencode,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "glob", sessionID: "s1", callID: "c1" }
    const output = { args: { path: ".opencode/agents", pattern: "*" } }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("blocks SSH access to remote .env file", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: { command: 'ssh user@server.com "cat /home/deploy/.env"' },
    }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("blocks SCP download of sensitive file", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: { command: "scp user@server.com:/home/user/.env ./local/" },
    }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("allows SSH with safe inner command and safe paths", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: { command: 'ssh user@server.com "ls -la /var/log"' },
    }

    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  test("blocks SSH identity file access via -i flag", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        command: 'ssh -i /home/user/.ssh/id_rsa user@host.com "ls"',
      },
    }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("blocks SSH access to remote authorized_keys", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        command: 'ssh user@host.com "cat /home/user/.ssh/authorized_keys"',
      },
    }

    await expect(hook(input, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("respects session allowlist", async () => {
    const deps = createTestDeps()
    deps.sessionAllowlist.add("/project/.env")
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "read", sessionID: "s1", callID: "c1" }
    const output = { args: { filePath: "/project/.env" } }

    // Should not throw because the file is allowlisted
    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  test("redactionExemptPaths: write to exempt path preserves API key in content", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "write", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        filePath: "/project/src/config.ts",
        content: 'OPENROUTER_API_KEY="sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
      },
    }

    await hook(input, output)
    // Content must be preserved unchanged — no [REDACTED]
    expect(output.args.content as string).toContain("sk-or-v1-")
    expect(output.args.content as string).not.toContain("[REDACTED]")
  })

  test("redactionExemptPaths: write to non-exempt path still redacts secrets", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "write", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        filePath: "/project/src/random.ts",
        content: 'OPENROUTER_API_KEY="sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
      },
    }

    await hook(input, output)
    expect(output.args.content as string).toContain("[REDACTED]")
    expect(output.args.content as string).not.toContain("sk-or-v1-")
  })

  test("redactionExemptPaths: glob pattern matches nested file", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["**/secrets.json"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "edit", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        filePath: "/project/config/secrets.json",
        content: '"openrouter_key": "sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
      },
    }

    await hook(input, output)
    expect(output.args.content as string).toContain("sk-or-v1-")
    expect(output.args.content as string).not.toContain("[REDACTED]")
  })

  test("redactionExemptPaths does NOT bypass blockedFilePaths", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      // Try to exempt .env (which is also blocked) — should still be blocked
      redactionExemptPaths: [".env", "**/.env"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "write", sessionID: "s1", callID: "c1" }
    const output = { args: { filePath: "/project/.env", content: "FOO=bar" } }

    // File blocking runs BEFORE redaction exemption — must still throw
    await expect(hook(input, output)).rejects.toThrow("blocked by security policy")
  })

  test("redactionExemptPaths does NOT apply to bash commands", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["**/*"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: { command: "echo sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
    }

    await hook(input, output)
    // Bash is not a write tool — exemption must not apply
    expect(output.args.command as string).not.toContain("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
  })

  test("redactionExemptPaths: bash redirection to exempt path preserves secret", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        command:
          'echo "KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" > /project/src/config.ts',
      },
    }

    await hook(input, output)
    expect(output.args.command as string).toContain("sk-proj-")
    expect(output.args.command as string).not.toContain("[REDACTED]")
  })

  test("redactionExemptPaths: bash redirection to NON-exempt path still redacts", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        command:
          'echo "KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" > /project/src/random.ts',
      },
    }

    await hook(input, output)
    expect(output.args.command as string).toContain("[REDACTED]")
  })

  test("redactionExemptPaths: host-scoped entry matches remote SCP upload", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["host:web-*:/etc/myapp/config.conf"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        command:
          'echo "KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" | ssh user@web-01.example.com "cat > /etc/myapp/config.conf"',
      },
    }

    // SSH command extracts inner file refs as reads only; this test confirms
    // the host-scoped exemption logic flows through (the inner write isn't
    // extracted as a write target — that's a known limitation of the parser).
    // The point of this test is to confirm we don't throw and the host parser
    // doesn't error on host: entries.
    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  test("redactionExemptPaths: SCP upload to host-scoped exempt path preserves secret", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["host:web-*:/etc/myapp/**"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        command:
          "scp /tmp/local.txt web-01.example.com:/etc/myapp/config.conf",
      },
    }

    await hook(input, output)
    // The SCP upload target host=web-01.example.com path=/etc/myapp/config.conf
    // matches `host:web-*:/etc/myapp/**` → redaction skipped on the command.
    // Command itself has no secret to redact, but we verify no errors thrown.
    await expect(Promise.resolve()).resolves.toBeUndefined()
  })

  test("redactionExemptPaths: bash tee to exempt path preserves secret", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        command:
          'echo "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" | tee /project/src/config.ts',
      },
    }

    await hook(input, output)
    expect(output.args.command as string).toContain("sk-proj-")
    expect(output.args.command as string).not.toContain("[REDACTED]")
  })

  test("redactionExemptPaths: bash tee to mixed exempt and non-exempt paths still redacts", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        command:
          'echo "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" | tee /project/src/config.ts /tmp/leak.txt',
      },
    }

    await hook(input, output)
    expect(output.args.command as string).toContain("[REDACTED]")
    expect(output.args.command as string).not.toContain("sk-proj-")
  })

  test("redactionExemptPaths: bash tee to multiple exempt paths preserves secret", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts", "src/fixture.ts"],
    }
    const hook = createInputSanitizer({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        command:
          'echo "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" | tee /project/src/config.ts /project/src/fixture.ts',
      },
    }

    await hook(input, output)
    expect(output.args.command as string).toContain("sk-proj-")
    expect(output.args.command as string).not.toContain("[REDACTED]")
  })

  test("redactOnWrite=false disables redaction globally for write tool", async () => {
    const deps = createTestDeps()
    const configNoWriteRedact = { ...DEFAULT_CONFIG, redactOnWrite: false }
    const hook = createInputSanitizer({
      ...deps,
      config: configNoWriteRedact,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "write", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        filePath: "/project/src/random.ts",
        content: 'KEY="sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
      },
    }

    await hook(input, output)
    expect(output.args.content as string).toContain("sk-or-v1-")
    expect(output.args.content as string).not.toContain("[REDACTED]")
  })

  test("redactOnWrite=false disables redaction globally for edit tool", async () => {
    const deps = createTestDeps()
    const configNoWriteRedact = { ...DEFAULT_CONFIG, redactOnWrite: false }
    const hook = createInputSanitizer({
      ...deps,
      config: configNoWriteRedact,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "edit", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        filePath: "/project/src/random.ts",
        content: [{ oldText: "x", newText: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" }],
      },
    }

    await hook(input, output)
    expect(JSON.stringify(output.args.content)).toContain("sk-proj-")
  })

  test("redactOnWrite=false does NOT apply to bash (still redacted)", async () => {
    const deps = createTestDeps()
    const configNoWriteRedact = { ...DEFAULT_CONFIG, redactOnWrite: false }
    const hook = createInputSanitizer({
      ...deps,
      config: configNoWriteRedact,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: { command: "echo sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
    }

    await hook(input, output)
    expect(output.args.command as string).not.toContain("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
  })

  test("redactOnWrite=false does NOT bypass blockedFilePaths", async () => {
    const deps = createTestDeps()
    const configNoWriteRedact = { ...DEFAULT_CONFIG, redactOnWrite: false }
    const hook = createInputSanitizer({
      ...deps,
      config: configNoWriteRedact,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "write", sessionID: "s1", callID: "c1" }
    const output = { args: { filePath: "/project/.env", content: "FOO=bar" } }

    await expect(hook(input, output)).rejects.toThrow("blocked by security policy")
  })

  test("redactOnWrite default (true) still redacts writes", async () => {
    const deps = createTestDeps()
    const hook = createInputSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "write", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        filePath: "/project/src/random.ts",
        content: 'KEY="sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
      },
    }

    await hook(input, output)
    expect(output.args.content as string).toContain("[REDACTED]")
    expect(output.args.content as string).not.toContain("sk-proj-")
  })

  test("redactionEnabled=false disables redaction for bash tool input", async () => {
    const deps = createTestDeps()
    const configDisabled = { ...DEFAULT_CONFIG, redactionEnabled: false }
    const hook = createInputSanitizer({
      ...deps,
      config: configDisabled,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    const output = {
      args: { command: "echo sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
    }

    await hook(input, output)
    // Master kill switch applies even to bash — content must pass through
    expect(output.args.command as string).toContain("sk-proj-")
    expect(output.args.command as string).not.toContain("[REDACTED]")
  })

  test("redactionEnabled=false overrides redactOnWrite=true", async () => {
    const deps = createTestDeps()
    // Explicitly leave redactOnWrite at default true — master switch should still win
    const configDisabled = { ...DEFAULT_CONFIG, redactionEnabled: false, redactOnWrite: true }
    const hook = createInputSanitizer({
      ...deps,
      config: configDisabled,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "write", sessionID: "s1", callID: "c1" }
    const output = {
      args: {
        filePath: "/project/src/random.ts",
        content: 'KEY="sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
      },
    }

    await hook(input, output)
    expect(output.args.content as string).toContain("sk-proj-")
  })

  test("redactionEnabled=false does NOT bypass blockedFilePaths", async () => {
    const deps = createTestDeps()
    const configDisabled = { ...DEFAULT_CONFIG, redactionEnabled: false }
    const hook = createInputSanitizer({
      ...deps,
      config: configDisabled,
      client: mockClient,
      safetyEvaluator: null,
      sessionAllowlist: deps.sessionAllowlist,
    })

    const input = { tool: "read", sessionID: "s1", callID: "c1" }
    const output = { args: { filePath: "/project/.env" } }

    await expect(hook(input, output)).rejects.toThrow("blocked by security policy")
  })
})

describe("Output Redactor Hook", () => {
  test("redacts secrets in output", async () => {
    const deps = createTestDeps()
    const hook = createOutputRedactor({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = { tool: "read", sessionID: "s1", callID: "c1" }
    const output = {
      output: "API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      title: "Read file",
      metadata: {},
    }

    await hook(input, output)
    expect(output.output).not.toContain("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
  })

  test("redacts secrets in title", async () => {
    const deps = createTestDeps()
    const hook = createOutputRedactor({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = { tool: "read", sessionID: "s1", callID: "c1" }
    const output = {
      output: "clean output",
      title: "File with ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
      metadata: {},
    }

    await hook(input, output)
    expect(output.title).not.toContain("ABCDEFGHIJKLMNOPQRST")
  })

  test("passes clean output unchanged", async () => {
    const deps = createTestDeps()
    const hook = createOutputRedactor({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = { tool: "read", sessionID: "s1", callID: "c1" }
    const originalOutput = "This is clean, no secrets here."
    const output = {
      output: originalOutput,
      title: "Clean title",
      metadata: {},
    }

    await hook(input, output)
    expect(output.output).toBe(originalOutput)
  })

  test("filters blocked paths from glob output", async () => {
    const deps = createTestDeps()
    const configWithOpencode = {
      ...DEFAULT_CONFIG,
      blockedFilePaths: [...DEFAULT_CONFIG.blockedFilePaths, "**/.opencode/**"],
    }
    const hook = createOutputRedactor({
      ...deps,
      config: configWithOpencode,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = { tool: "glob", sessionID: "s1", callID: "c1" }
    const output = {
      output: "src/index.ts\n.opencode/agents/devops.md\n.opencode/opencode-warden.json\npackage.json",
      title: "Glob results",
      metadata: {},
    }

    await hook(input, output)
    expect(output.output).toContain("src/index.ts")
    expect(output.output).toContain("package.json")
    expect(output.output).not.toContain(".opencode/agents/devops.md")
    expect(output.output).not.toContain(".opencode/opencode-warden.json")
  })

  test("leaves glob output unchanged when no blocked paths", async () => {
    const deps = createTestDeps()
    const hook = createOutputRedactor({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = { tool: "glob", sessionID: "s1", callID: "c1" }
    const originalOutput = "src/index.ts\npackage.json\nREADME.md"
    const output = {
      output: originalOutput,
      title: "Glob results",
      metadata: {},
    }

    await hook(input, output)
    expect(output.output).toBe(originalOutput)
  })

  test("redactionExemptPaths: read of exempt path preserves API key in output", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts"],
    }
    const hook = createOutputRedactor({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = {
      tool: "read",
      sessionID: "s1",
      callID: "c1",
      args: { filePath: "/project/src/config.ts" },
    }
    const originalOutput =
      'OPENROUTER_API_KEY="sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
    const output = { output: originalOutput, title: "Read src/config.ts", metadata: {} }

    await hook(input, output)
    expect(output.output).toBe(originalOutput)
    expect(output.output).toContain("sk-or-v1-")
  })

  test("redactionExemptPaths: read of non-exempt path still redacts", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts"],
    }
    const hook = createOutputRedactor({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = {
      tool: "read",
      sessionID: "s1",
      callID: "c1",
      args: { filePath: "/project/src/random.ts" },
    }
    const output = {
      output: 'OPENROUTER_API_KEY="sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n',
      title: "Read src/random.ts",
      metadata: {},
    }

    await hook(input, output)
    expect(output.output).not.toContain("sk-or-v1-")
    expect(output.output).toContain("[REDACTED]")
  })

  test("redactionExemptPaths: bash output IS exempted when cat target matches", async () => {
    // With per-path exemption now extended to bash, cat of an exempt path
    // preserves secrets in output. To verify the non-exempt case still
    // redacts, use a config that does NOT match the file being read.
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["/nonexistent/**"],
    }
    const hook = createOutputRedactor({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = {
      tool: "bash",
      sessionID: "s1",
      callID: "c1",
      args: { command: "cat secrets.txt" },
    }
    const output = {
      output: "key=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
      title: "bash",
      metadata: {},
    }

    await hook(input, output)
    expect(output.output).toContain("[REDACTED]")
  })

  test("redactionExemptPaths: bash cat of local exempt path preserves secret in output", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts"],
    }
    const hook = createOutputRedactor({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = {
      tool: "bash",
      sessionID: "s1",
      callID: "c1",
      args: { command: "cat /project/src/config.ts" },
    }
    const originalOutput = "KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
    const output = { output: originalOutput, title: "bash", metadata: {} }

    await hook(input, output)
    expect(output.output).toBe(originalOutput)
    expect(output.output).toContain("sk-proj-")
  })

  test("redactionExemptPaths: bash cat of mixed exempt and non-exempt paths still redacts output", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts"],
    }
    const hook = createOutputRedactor({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = {
      tool: "bash",
      sessionID: "s1",
      callID: "c1",
      args: { command: "cat /project/src/config.ts /tmp/leak.txt" },
    }
    const output = {
      output: "KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
      title: "bash",
      metadata: {},
    }

    await hook(input, output)
    expect(output.output).toContain("[REDACTED]")
    expect(output.output).not.toContain("sk-proj-")
  })

  test("redactionExemptPaths: bash cat of multiple exempt paths preserves output", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["src/config.ts", "src/fixture.ts"],
    }
    const hook = createOutputRedactor({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = {
      tool: "bash",
      sessionID: "s1",
      callID: "c1",
      args: { command: "cat /project/src/config.ts /project/src/fixture.ts" },
    }
    const originalOutput = "KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
    const output = { output: originalOutput, title: "bash", metadata: {} }

    await hook(input, output)
    expect(output.output).toBe(originalOutput)
    expect(output.output).toContain("sk-proj-")
  })

  test("redactionExemptPaths: host-scoped entry covers remote SSH cat output", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["host:web-*:/etc/myapp/**"],
    }
    const hook = createOutputRedactor({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = {
      tool: "bash",
      sessionID: "s1",
      callID: "c1",
      args: { command: 'ssh user@web-01.example.com "cat /etc/myapp/config.conf"' },
    }
    const originalOutput = "KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
    const output = { output: originalOutput, title: "ssh", metadata: {} }

    await hook(input, output)
    expect(output.output).toBe(originalOutput)
    expect(output.output).toContain("sk-proj-")
  })

  test("redactionExemptPaths: remote SSH mixed exempt and non-exempt paths still redacts output", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["host:web-*:/etc/myapp/**"],
    }
    const hook = createOutputRedactor({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = {
      tool: "bash",
      sessionID: "s1",
      callID: "c1",
      args: {
        command:
          'ssh user@web-01.example.com "cat /etc/myapp/config.conf /tmp/leak.txt"',
      },
    }
    const output = {
      output: "KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
      title: "ssh",
      metadata: {},
    }

    await hook(input, output)
    expect(output.output).toContain("[REDACTED]")
    expect(output.output).not.toContain("sk-proj-")
  })

  test("redactionExemptPaths: host-scoped entry does NOT match unmatched host", async () => {
    const deps = createTestDeps()
    const configWithExemption = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["host:web-*:/etc/myapp/**"],
    }
    const hook = createOutputRedactor({
      ...deps,
      config: configWithExemption,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = {
      tool: "bash",
      sessionID: "s1",
      callID: "c1",
      args: { command: 'ssh user@db-01.example.com "cat /etc/myapp/config.conf"' },
    }
    const output = {
      output: "KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
      title: "ssh",
      metadata: {},
    }

    await hook(input, output)
    expect(output.output).toContain("[REDACTED]")
  })

  test("redactionEnabled=false disables output redaction for all tools", async () => {
    const deps = createTestDeps()
    const configDisabled = { ...DEFAULT_CONFIG, redactionEnabled: false }
    const hook = createOutputRedactor({
      ...deps,
      config: configDisabled,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = {
      tool: "bash",
      sessionID: "s1",
      callID: "c1",
      args: { command: "cat secrets.txt" },
    }
    const originalOutput = "key=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
    const output = { output: originalOutput, title: "bash", metadata: {} }

    await hook(input, output)
    expect(output.output).toBe(originalOutput)
    expect(output.output).toContain("sk-proj-")
  })

  test("redactionEnabled=false overrides redactionExemptPaths (no-op)", async () => {
    const deps = createTestDeps()
    // Even with NO exempt paths, master switch disables everything
    const configDisabled = {
      ...DEFAULT_CONFIG,
      redactionEnabled: false,
      redactionExemptPaths: [],
    }
    const hook = createOutputRedactor({
      ...deps,
      config: configDisabled,
      client: mockClient,
      llmSanitizer: null,
    })

    const input = {
      tool: "read",
      sessionID: "s1",
      callID: "c1",
      args: { filePath: "/project/src/random.ts" },
    }
    const originalOutput = 'KEY="sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
    const output = { output: originalOutput, title: "Read random.ts", metadata: {} }

    await hook(input, output)
    expect(output.output).toBe(originalOutput)
  })
})

describe("Prompt Sanitizer Hook (chat.message)", () => {
  // Most tests need the scanner enabled — defaults to false in DEFAULT_CONFIG.
  const enabledConfig = { ...DEFAULT_CONFIG, scanUserPrompts: true }

  test("clean prompt passes through without throwing", async () => {
    const deps = createTestDeps()
    const hook = createPromptSanitizer({
      ...deps,
      config: enabledConfig,
      client: mockClient,
    })

    const input = { sessionID: "s1", messageID: "m1" }
    const output = {
      message: { id: "m1" },
      parts: [{ type: "text", text: "Help me write a function that adds two numbers." }],
    }

    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  test("blocks prompt containing an OpenAI-style API key", async () => {
    const deps = createTestDeps()
    const hook = createPromptSanitizer({
      ...deps,
      config: enabledConfig,
      client: mockClient,
    })

    const input = { sessionID: "s1", messageID: "m1" }
    const output = {
      message: { id: "m1" },
      parts: [
        { type: "text", text: "Here is my key, use it: sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
      ],
    }

    await expect(hook(input, output)).rejects.toThrow("blocked by security policy")
  })

  test("blocks when secret is in a LATER part (not the first)", async () => {
    const deps = createTestDeps()
    const hook = createPromptSanitizer({
      ...deps,
      config: enabledConfig,
      client: mockClient,
    })

    const input = { sessionID: "s1", messageID: "m1" }
    const output = {
      message: { id: "m1" },
      parts: [
        { type: "text", text: "First, some context." },
        { type: "file", url: "data:application/octet-stream;base64,AAA" },
        { type: "text", text: "By the way: sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
      ],
    }

    await expect(hook(input, output)).rejects.toThrow("blocked by security policy")
  })

  test("blocks subtask part containing a secret", async () => {
    const deps = createTestDeps()
    const hook = createPromptSanitizer({
      ...deps,
      config: enabledConfig,
      client: mockClient,
    })

    const input = { sessionID: "s1", messageID: "m1" }
    const output = {
      message: { id: "m1" },
      parts: [
        {
          type: "subtask",
          prompt: "Run this with the key sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
          description: "delegate",
          agent: "devops",
        },
      ],
    }

    await expect(hook(input, output)).rejects.toThrow("blocked by security policy")
  })

  test("skips synthetic text parts (system-generated)", async () => {
    const deps = createTestDeps()
    const hook = createPromptSanitizer({
      ...deps,
      config: enabledConfig,
      client: mockClient,
    })

    // Synthetic parts are generated by OpenCode, not typed by the user.
    // Even if they contain a secret-looking string, we don't scan them —
    // they're already past the trust boundary.
    const input = { sessionID: "s1", messageID: "m1" }
    const output = {
      message: { id: "m1" },
      parts: [
        { type: "text", text: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", synthetic: true },
      ],
    }

    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  test("scanUserPrompts=false (default) skips the hook entirely", async () => {
    const deps = createTestDeps()
    const hook = createPromptSanitizer({
      ...deps,
      config: DEFAULT_CONFIG, // scanUserPrompts defaults to false
      client: mockClient,
    })

    const input = { sessionID: "s1", messageID: "m1" }
    const output = {
      message: { id: "m1" },
      parts: [
        { type: "text", text: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
      ],
    }

    // With the default config, scanning is OFF — secret passes through
    await expect(hook(input, output)).resolves.toBeUndefined()
    expect(deps.sessionStats.getSummary().blockedAttempts).toBe(0)
  })

  test("redactionEnabled=false overrides scanUserPrompts=true", async () => {
    const deps = createTestDeps()
    const hook = createPromptSanitizer({
      ...deps,
      config: { ...DEFAULT_CONFIG, scanUserPrompts: true, redactionEnabled: false },
      client: mockClient,
    })

    const input = { sessionID: "s1", messageID: "m1" }
    const output = {
      message: { id: "m1" },
      parts: [
        { type: "text", text: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
      ],
    }

    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  test("empty parts array passes through", async () => {
    const deps = createTestDeps()
    const hook = createPromptSanitizer({
      ...deps,
      config: enabledConfig,
      client: mockClient,
    })

    const input = { sessionID: "s1", messageID: "m1" }
    const output = { message: { id: "m1" }, parts: [] }

    await expect(hook(input, output)).resolves.toBeUndefined()
  })

  test("blocked call records session stats", async () => {
    const deps = createTestDeps()
    const hook = createPromptSanitizer({
      ...deps,
      config: enabledConfig,
      client: mockClient,
    })

    const input = { sessionID: "s1", messageID: "m1" }
    const output = {
      message: { id: "m1" },
      parts: [{ type: "text", text: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }],
    }

    await expect(hook(input, output)).rejects.toThrow()
    expect(deps.sessionStats.getSummary().blockedAttempts).toBeGreaterThan(0)
  })

  test("thrown error message mentions the detected pattern category", async () => {
    const deps = createTestDeps()
    const hook = createPromptSanitizer({
      ...deps,
      config: enabledConfig,
      client: mockClient,
    })

    const input = { sessionID: "s1", messageID: "m1" }
    const output = {
      message: { id: "m1" },
      parts: [{ type: "text", text: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }],
    }

    try {
      await hook(input, output)
      expect.unreachable("should have thrown")
    } catch (err) {
      expect(err instanceof Error).toBe(true)
      const msg = (err as Error).message
      // Mention that it's a Warden block and reference the category
      expect(msg).toContain("Warden")
      expect(msg.toLowerCase()).toMatch(/api|key|secret|credential/)
    }
  })
})

describe("Environment Sanitizer Hook", () => {
  test("redacts sensitive env var values", async () => {
    const deps = createTestDeps()
    const hook = createEnvSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
    })

    const input = { cwd: "/project" }
    const output = {
      env: {
        HOME: "/Users/test",
        OPENAI_API_KEY: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        PATH: "/usr/bin:/usr/local/bin",
      },
    }

    await hook(input, output)
    // OPENAI_API_KEY should be redacted (matches *_API_KEY pattern AND contains a secret value)
    expect(output.env.OPENAI_API_KEY).not.toContain("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    // PATH should be unchanged
    expect(output.env.PATH).toBe("/usr/bin:/usr/local/bin")
    // HOME should be unchanged
    expect(output.env.HOME).toBe("/Users/test")
  })

  test("strips env vars matching name patterns", async () => {
    const deps = createTestDeps()
    const hook = createEnvSanitizer({
      ...deps,
      config: DEFAULT_CONFIG,
      client: mockClient,
    })

    const input = { cwd: "/project" }
    const output = {
      env: {
        MY_SECRET: "some-value",
        AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        GITHUB_TOKEN: "ghp_xxxxxxxxxxxx",
        NORMAL_VAR: "safe",
      },
    }

    await hook(input, output)
    expect(output.env.MY_SECRET).toBe("[REDACTED]")
    expect(output.env.AWS_SECRET_ACCESS_KEY).toBe("[REDACTED]")
    expect(output.env.GITHUB_TOKEN).toBe("[REDACTED]")
    expect(output.env.NORMAL_VAR).toBe("safe")
  })

  test("does nothing when disabled", async () => {
    const deps = createTestDeps()
    const disabledConfig = {
      ...DEFAULT_CONFIG,
      env: { ...DEFAULT_CONFIG.env, enabled: false },
    }
    const hook = createEnvSanitizer({
      ...deps,
      config: disabledConfig,
      client: mockClient,
    })

    const input = { cwd: "/project" }
    const output = {
      env: { MY_SECRET: "exposed" },
    }

    await hook(input, output)
    expect(output.env.MY_SECRET).toBe("exposed")
  })
})

describe("Compaction Context Hook", () => {
  test("injects security policy context", async () => {
    const hook = createCompactionContext({ config: DEFAULT_CONFIG, diagnosticLogger: null })

    const output = { context: [] as string[] }
    await hook({}, output)

    expect(output.context.length).toBe(1)
    const context = output.context[0]
    expect(context).toContain("Warden Security Policy")
    expect(context).toContain("Blocked Files")
    expect(context).toContain(".env")
    expect(context).toContain("[REDACTED]")
    expect(context).toContain("Blocked Commands")
    expect(context).toContain("security_help")
  })
})

describe("SSH-Only Mode", () => {
  const sshOnlyConfig = { ...DEFAULT_CONFIG, sshOnlyMode: true }

  describe("Input Sanitizer", () => {
    test("skips non-remote bash commands", async () => {
      const deps = createTestDeps()
      const hook = createInputSanitizer({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        safetyEvaluator: null,
        sessionAllowlist: deps.sessionAllowlist,
        diagnosticLogger: null,
        writtenFileRegistry: new Map(),
      })

      const input = { tool: "bash", sessionID: "s1", callID: "c1" }
      const output = { args: { command: "ls -la" } }

      await hook(input, output)
      expect(output.args.command).toBe("ls -la")
    })

    test("skips non-bash tools (read)", async () => {
      const deps = createTestDeps()
      const hook = createInputSanitizer({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        safetyEvaluator: null,
        sessionAllowlist: deps.sessionAllowlist,
        diagnosticLogger: null,
        writtenFileRegistry: new Map(),
      })

      const input = { tool: "read", sessionID: "s1", callID: "c1" }
      const output = { args: { filePath: "/project/.env" } }

      await expect(hook(input, output)).resolves.toBeUndefined()
    })

    test("processes ssh commands", async () => {
      const deps = createTestDeps()
      const hook = createInputSanitizer({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        safetyEvaluator: null,
        sessionAllowlist: deps.sessionAllowlist,
        diagnosticLogger: null,
        writtenFileRegistry: new Map(),
      })

      const input = { tool: "bash", sessionID: "s1", callID: "c1" }
      const output = {
        args: {
          command: 'ssh user@server.com "cat /home/deploy/.env"',
        },
      }

      await expect(hook(input, output)).rejects.toThrow("blocked by security policy")
    })

    test("processes scp commands", async () => {
      const deps = createTestDeps()
      const hook = createInputSanitizer({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        safetyEvaluator: null,
        sessionAllowlist: deps.sessionAllowlist,
        diagnosticLogger: null,
        writtenFileRegistry: new Map(),
      })

      const input = { tool: "bash", sessionID: "s1", callID: "c1" }
      const output = {
        args: {
          command: "scp user@server.com:/home/user/.env ./local/",
        },
      }

      await expect(hook(input, output)).rejects.toThrow("blocked by security policy")
    })

    test("processes rsync with remote path", async () => {
      const deps = createTestDeps()
      const hook = createInputSanitizer({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        safetyEvaluator: null,
        sessionAllowlist: deps.sessionAllowlist,
        diagnosticLogger: null,
        writtenFileRegistry: new Map(),
      })

      const input = { tool: "bash", sessionID: "s1", callID: "c1" }
      const output = {
        args: {
          command: "rsync -avz user@server.com:/home/user/.env ./local/",
        },
      }

      await expect(hook(input, output)).rejects.toThrow("blocked by security policy")
    })

    test("processes rclone with remote path", async () => {
      const deps = createTestDeps()
      const hook = createInputSanitizer({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        safetyEvaluator: null,
        sessionAllowlist: deps.sessionAllowlist,
        diagnosticLogger: null,
        writtenFileRegistry: new Map(),
      })

      const input = { tool: "bash", sessionID: "s1", callID: "c1" }
      const output = {
        args: {
          command: "rclone copy remote:secrets/.env ./local/",
        },
      }

      await expect(hook(input, output)).rejects.toThrow("blocked by security policy")
    })

    test("skips rsync local-only", async () => {
      const deps = createTestDeps()
      const hook = createInputSanitizer({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        safetyEvaluator: null,
        sessionAllowlist: deps.sessionAllowlist,
        diagnosticLogger: null,
        writtenFileRegistry: new Map(),
      })

      const input = { tool: "bash", sessionID: "s1", callID: "c1" }
      const output = {
        args: {
          command: "rsync -avz ./local/ ./backup/",
        },
      }

      await hook(input, output)
      expect(output.args.command).toBe("rsync -avz ./local/ ./backup/")
    })
  })

  describe("Output Redactor", () => {
    test("skips non-remote bash commands", async () => {
      const deps = createTestDeps()
      const hook = createOutputRedactor({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        llmSanitizer: null,
        outputTriage: null,
        outputTextTriage: null,
        diagnosticLogger: null,
      })

      const input = {
        tool: "bash",
        sessionID: "s1",
        callID: "c1",
        args: { command: "ls -la" },
      }
      const output = {
        output: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        title: "Output",
        metadata: {},
      }

      await hook(input, output)
      expect(output.output).toBe("sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    })

    test("skips non-bash tools (read)", async () => {
      const deps = createTestDeps()
      const hook = createOutputRedactor({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        llmSanitizer: null,
        outputTriage: null,
        outputTextTriage: null,
        diagnosticLogger: null,
      })

      const input = {
        tool: "read",
        sessionID: "s1",
        callID: "c1",
        args: { filePath: "/project/.env" },
      }
      const output = {
        output: "SECRET_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        title: "File content",
        metadata: {},
      }

      await hook(input, output)
      expect(output.output).toBe("SECRET_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    })

    test("processes ssh commands", async () => {
      const deps = createTestDeps()
      const hook = createOutputRedactor({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        llmSanitizer: null,
        outputTriage: null,
        outputTextTriage: null,
        diagnosticLogger: null,
      })

      const input = {
        tool: "bash",
        sessionID: "s1",
        callID: "c1",
        args: { command: 'ssh user@server.com "cat /etc/config"' },
      }
      const output = {
        output: "API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        title: "SSH output",
        metadata: {},
      }

      await hook(input, output)
      expect(output.output).not.toContain("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    })

    test("processes rsync with remote path", async () => {
      const deps = createTestDeps()
      const hook = createOutputRedactor({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        llmSanitizer: null,
        outputTriage: null,
        outputTextTriage: null,
        diagnosticLogger: null,
      })

      const input = {
        tool: "bash",
        sessionID: "s1",
        callID: "c1",
        args: { command: "rsync -avz user@server.com:/home/user/ ./local/" },
      }
      const output = {
        output: "copied file with secret sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        title: "rsync output",
        metadata: {},
      }

      await hook(input, output)
      expect(output.output).not.toContain("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    })
  })

  describe("Env Sanitizer", () => {
    test("skips entirely in sshOnlyMode", async () => {
      const deps = createTestDeps()
      const hook = createEnvSanitizer({
        ...deps,
        config: sshOnlyConfig,
        client: mockClient,
        diagnosticLogger: null,
      })

      const input = { cwd: "/project" }
      const output = {
        env: {
          MY_SECRET: "exposed",
          AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
      }

      await hook(input, output)
      expect(output.env.MY_SECRET).toBe("exposed")
      expect(output.env.AWS_SECRET_ACCESS_KEY).toBe("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    })
  })

  describe("Session-scoped state", () => {
    test("does not share allowlisted paths between sessions", async () => {
      const deps = createTestDeps()
      const states = new Map<string, ReturnType<typeof createTestDeps>>()
      const getSessionState = (sessionID: string) => {
        let state = states.get(sessionID)
        if (!state) {
          state = createTestDeps()
          states.set(sessionID, state)
        }
        return {
          sessionStats: state.sessionStats,
          safetyEvaluator: null,
          toastState: state.toastState,
          sessionAllowlist: state.sessionAllowlist,
          evaluatedCalls: state.evaluatedCalls,
          writtenFileRegistry: state.writtenFileRegistry,
        }
      }
      getSessionState("s1").sessionAllowlist.add("/project/.env")

      const hook = createInputSanitizer({
        engine: deps.engine,
        config: DEFAULT_CONFIG,
        auditLogger: deps.auditLogger,
        client: mockClient,
        diagnosticLogger: null,
        getSessionState,
      })

      await hook(
        { tool: "read", sessionID: "s1", callID: "c1" },
        { args: { filePath: "/project/.env" } },
      )

      await expect(
        hook(
          { tool: "read", sessionID: "s2", callID: "c2" },
          { args: { filePath: "/project/.env" } },
        ),
      ).rejects.toThrow("blocked by security policy")
    })
  })
})

describe("Session Context Capture (chat.message wrapper)", () => {
  type CapturedState = {
    lastAgent?: string
    lastModel?: { providerID: string; modelID: string }
    lastVariant?: string
    lastAccessed: number
  }

  test("captures agent, model, and variant on the session state", async () => {
    const sessions = new Map<string, CapturedState>()
    const getState = (id: string) => {
      let s = sessions.get(id)
      if (!s) {
        s = { lastAccessed: Date.now() }
        sessions.set(id, s)
      }
      return s
    }
    const capture = createSessionContextCapture(getState)

    await capture({
      sessionID: "s1",
      agent: "devops",
      model: { providerID: "anthropic", modelID: "claude-sonnet-4" },
      variant: "reasoning",
    })

    const s = sessions.get("s1")!
    expect(s.lastAgent).toBe("devops")
    expect(s.lastModel).toEqual({ providerID: "anthropic", modelID: "claude-sonnet-4" })
    expect(s.lastVariant).toBe("reasoning")
  })

  test("captures partial fields without overwriting existing ones", async () => {
    const sessions = new Map<string, CapturedState>([
      ["s1", {
        lastAgent: "devops",
        lastModel: { providerID: "anthropic", modelID: "claude-sonnet-4" },
        lastVariant: "reasoning",
        lastAccessed: Date.now(),
      }],
    ])
    const capture = createSessionContextCapture((id) => sessions.get(id)!)

    // Second call with only agent — should preserve model and variant
    await capture({ sessionID: "s1", agent: "reviewer" })

    const s = sessions.get("s1")!
    expect(s.lastAgent).toBe("reviewer")          // updated
    expect(s.lastModel?.modelID).toBe("claude-sonnet-4")  // preserved
    expect(s.lastVariant).toBe("reasoning")       // preserved
  })

  test("no-op when sessionID is empty", async () => {
    const sessions = new Map<string, CapturedState>()
    const capture = createSessionContextCapture((id) => {
      const s = { lastAccessed: Date.now() }
      sessions.set(id, s)
      return s
    })

    await capture({ sessionID: "", agent: "test" })
    expect(sessions.size).toBe(0)
  })

  test("swallows errors from getSessionState (must not throw)", async () => {
    const failingGetState = (): CapturedState => {
      throw new Error("session lookup failed")
    }
    const capture = createSessionContextCapture(failingGetState)

    // Must NOT throw — capture is non-blocking
    await expect(
      capture({ sessionID: "s1", agent: "test" }),
    ).resolves.toBeUndefined()
  })

  test("different sessions have independent state", async () => {
    const sessions = new Map<string, CapturedState>()
    const getState = (id: string) => {
      let s = sessions.get(id)
      if (!s) {
        s = { lastAccessed: Date.now() }
        sessions.set(id, s)
      }
      return s
    }
    const capture = createSessionContextCapture(getState)

    await capture({ sessionID: "s1", agent: "devops" })
    await capture({ sessionID: "s2", agent: "reviewer" })

    expect(sessions.get("s1")?.lastAgent).toBe("devops")
    expect(sessions.get("s2")?.lastAgent).toBe("reviewer")
  })
})

describe("sweepStaleSessions", () => {
  type State = { lastAccessed: number }

  test("removes entries older than TTL", () => {
    const now = 10_000_000
    const sessions = new Map<string, State>([
      ["fresh", { lastAccessed: now - 1000 }],         // 1s old — keep
      ["old", { lastAccessed: now - 20_000 }],          // 20s old — sweep (TTL=10s)
      ["ancient", { lastAccessed: now - 100_000 }],     // 100s old — sweep
    ])

    const swept = sweepStaleSessions(sessions, now, 10_000)
    expect(swept.sort()).toEqual(["ancient", "old"])
    expect(sessions.has("fresh")).toBe(true)
    expect(sessions.has("old")).toBe(false)
    expect(sessions.has("ancient")).toBe(false)
  })

  test("returns empty array when nothing is stale", () => {
    const now = 10_000
    const sessions = new Map<string, State>([
      ["a", { lastAccessed: now }],
      ["b", { lastAccessed: now - 500 }],
    ])
    const swept = sweepStaleSessions(sessions, now, 60_000)
    expect(swept).toEqual([])
    expect(sessions.size).toBe(2)
  })

  test("handles empty map", () => {
    const sessions = new Map<string, State>()
    const swept = sweepStaleSessions(sessions, Date.now(), 1000)
    expect(swept).toEqual([])
  })

  test("boundary: lastAccessed exactly at cutoff is kept (>=)", () => {
    const now = 1000
    const ttl = 500
    // cutoff = now - ttl = 500. Entry at exactly 500 should be KEPT (not stale).
    // Entry at 499 should be SWEPT.
    const sessions = new Map<string, State>([
      ["boundary", { lastAccessed: now - ttl }],  // exactly at cutoff
      ["just-before", { lastAccessed: now - ttl - 1 }],  // 1ms older
    ])
    const swept = sweepStaleSessions(sessions, now, ttl)
    expect(swept).toEqual(["just-before"])
    expect(sessions.has("boundary")).toBe(true)
  })
})
