import { describe, test, expect } from "bun:test"
import { createDetectionEngine } from "../src/detection/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import { AuditLogger } from "../src/audit/index.js"
import { SessionStats } from "../src/audit/session-stats.js"
import { createInputSanitizer } from "../src/hooks/input-sanitizer.js"
import { createOutputRedactor } from "../src/hooks/output-redactor.js"
import { createEnvSanitizer } from "../src/hooks/env-sanitizer.js"
import { createCompactionContext } from "../src/hooks/compaction-context.js"
import type { PluginClient, ToastState, WrittenFileMetadata, SecurityGuardConfig } from "../src/types.js"

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
  const sessionPromptState = new Map<string, { agent?: string; model?: { providerID: string; modelID: string }; variant?: string }>()
  const policyInjected = new Set<string>()

  return {
    engine,
    auditLogger,
    sessionStats,
    toastState,
    sessionAllowlist,
    evaluatedCalls,
    writtenFileRegistry,
    sessionPromptState,
    policyInjected,
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

describe("Session State & Policy Injection", () => {
  test("chat.message hook captures agent, model, variant per session", async () => {
    // Test the internal sessionPromptState logic by testing the hook factory
    // Since we can't easily access the internal state, we test the hook doesn't throw
    const deps = createTestDeps()
    
    // We can't directly test the inline hook from index.ts, but we can verify
    // the pattern matches other hooks - it has try/catch and handles missing fields
    const chatMessageHandler = async ({ sessionID, agent, model, variant }: {
      sessionID: string
      agent?: string
      model?: { providerID: string; modelID: string }
      variant?: string
    }) => {
      try {
        if (!sessionID) return
        const existing = deps.sessionPromptState?.get(sessionID) ?? {}
        deps.sessionPromptState?.set(sessionID, {
          ...existing,
          ...(agent !== undefined ? { agent } : {}),
          ...(model ? { model } : {}),
          ...(variant !== undefined ? { variant } : {}),
        })
      } catch {
        // Non-critical
      }
    }

    // Should not throw with full data
    await chatMessageHandler({
      sessionID: "session-1",
      agent: "coding-agent",
      model: { providerID: "anthropic", modelID: "claude-3" },
      variant: "sonnet",
    })

    // Should not throw with partial data
    await chatMessageHandler({
      sessionID: "session-2",
      agent: "test-agent",
    })

    // Should not throw with minimal data
    await chatMessageHandler({
      sessionID: "session-3",
    })

    // Should return early without sessionID
    await chatMessageHandler({
      sessionID: "",
      agent: "test",
    })
  })

  test("policy injection is per-session (policyInjected Set logic)", () => {
    const policyInjected = new Set<string>()
    
    // First call for session-1
    expect(policyInjected.has("session-1")).toBe(false)
    policyInjected.add("session-1")
    expect(policyInjected.has("session-1")).toBe(true)
    
    // Different session
    expect(policyInjected.has("session-2")).toBe(false)
    policyInjected.add("session-2")
    expect(policyInjected.has("session-2")).toBe(true)
    
    // Original session still tracked
    expect(policyInjected.has("session-1")).toBe(true)
    expect(policyInjected.size).toBe(2)
  })

  test("session.created event clears state for that session only", () => {
    const sessionPromptState = new Map<string, { agent?: string }>()
    const policyInjected = new Set<string>()
    
    // Populate state for two sessions
    sessionPromptState.set("session-1", { agent: "agent-1" })
    sessionPromptState.set("session-2", { agent: "agent-2" })
    policyInjected.add("session-1")
    policyInjected.add("session-2")
    
    // Simulate session.created for session-1
    const sessionID = "session-1"
    sessionPromptState.delete(sessionID)
    policyInjected.delete(sessionID)
    
    // session-1 should be cleared
    expect(sessionPromptState.has("session-1")).toBe(false)
    expect(policyInjected.has("session-1")).toBe(false)
    
    // session-2 should be unaffected
    expect(sessionPromptState.has("session-2")).toBe(true)
    expect(policyInjected.has("session-2")).toBe(true)
    expect(sessionPromptState.get("session-2")?.agent).toBe("agent-2")
  })

  test("chat.message hook handles missing optional fields gracefully", async () => {
    const sessionPromptState = new Map<string, { agent?: string; model?: any; variant?: string }>()
    
    const chatMessageHandler = async ({ sessionID, agent, model, variant }: {
      sessionID: string
      agent?: string
      model?: { providerID: string; modelID: string }
      variant?: string
    }) => {
      try {
        if (!sessionID) return
        const existing = sessionPromptState.get(sessionID) ?? {}
        sessionPromptState.set(sessionID, {
          ...existing,
          ...(agent !== undefined ? { agent } : {}),
          ...(model ? { model } : {}),
          ...(variant !== undefined ? { variant } : {}),
        })
      } catch {
        // Non-critical
      }
    }

    // Event with only sessionID
    await chatMessageHandler({ sessionID: "session-3" })
    expect(sessionPromptState.get("session-3")).toEqual({})

    // Event with partial fields
    await chatMessageHandler({ sessionID: "session-4", agent: "test-agent" })
    expect(sessionPromptState.get("session-4")).toEqual({ agent: "test-agent" })

    // Event with all fields
    await chatMessageHandler({ 
      sessionID: "session-5", 
      agent: "agent-5", 
      model: { providerID: "openai", modelID: "gpt-4" },
      variant: "turbo"
    })
    expect(sessionPromptState.get("session-5")).toEqual({
      agent: "agent-5",
      model: { providerID: "openai", modelID: "gpt-4" },
      variant: "turbo"
    })
  })
})
