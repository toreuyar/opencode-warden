import { describe, test, expect } from "bun:test"
import { createDetectionEngine } from "../src/detection/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import { AuditLogger } from "../src/audit/index.js"
import { SessionStats } from "../src/audit/session-stats.js"
import { createInputSanitizer } from "../src/hooks/input-sanitizer.js"
import { createOutputRedactor } from "../src/hooks/output-redactor.js"
import { createEnvSanitizer } from "../src/hooks/env-sanitizer.js"
import { createCompactionContext } from "../src/hooks/compaction-context.js"
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
})
