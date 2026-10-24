import { describe, test, expect } from "bun:test"
import { createDetectionEngine } from "../src/detection/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import { AuditLogger } from "../src/audit/index.js"
import { SessionStats } from "../src/audit/session-stats.js"
import { createInputSanitizer } from "../src/hooks/input-sanitizer.js"
import { createOutputRedactor } from "../src/hooks/output-redactor.js"
import { createPermissionHandler } from "../src/hooks/permission-handler.js"
import { LlmSanitizer } from "../src/llm/index.js"
import { SafetyEvaluator } from "../src/llm/safety-evaluator.js"
import { ProviderChain } from "../src/llm/provider-chain.js"
import type {
  PluginClient,
  SecurityGuardConfig,
  ToastState,
  WrittenFileMetadata,
  LlmProviderConfig,
} from "../src/types.js"

const SECRET = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

const mockClient: PluginClient = {
  app: { log: async () => undefined },
  tui: { showToast: async () => undefined },
  session: { prompt: async () => undefined },
}

const testAuditConfig = { ...DEFAULT_CONFIG.audit, enabled: false }

function makeProvider(): LlmProviderConfig {
  return {
    name: "test",
    cooldown: 0,
    baseUrl: "http://localhost:11434/v1",
    model: "test",
    apiKey: "",
    timeout: 5000,
    temperature: 0,
    headers: {},
    healthCheckPath: "/models",
    completionsPath: "/chat/completions",
  }
}

function createTestDeps() {
  return {
    engine: createDetectionEngine(DEFAULT_CONFIG),
    auditLogger: new AuditLogger(testAuditConfig),
    sessionStats: new SessionStats("test"),
    toastState: { lastToastTime: 0, minInterval: 0 } as ToastState,
    sessionAllowlist: new Set<string>(),
    evaluatedCalls: new Set<string>(),
    writtenFileRegistry: new Map<string, WrittenFileMetadata>(),
    diagnosticLogger: null,
    outputTriage: null,
    outputTextTriage: null,
  }
}

function makeInputSanitizer(config: SecurityGuardConfig) {
  const deps = createTestDeps()
  const hook = createInputSanitizer({
    ...deps,
    config,
    client: mockClient,
    safetyEvaluator: null,
    sessionAllowlist: deps.sessionAllowlist,
  })
  return { hook, deps }
}

function makeOutputRedactor(config: SecurityGuardConfig) {
  const deps = createTestDeps()
  const hook = createOutputRedactor({
    ...deps,
    config,
    client: mockClient,
    llmSanitizer: null,
  })
  return { hook, deps }
}

function makePermissionConfig(overrides: {
  blockedTools?: string[]
  sshOnlyMode?: boolean
} = {}): SecurityGuardConfig {
  return {
    ...DEFAULT_CONFIG,
    blockedTools: overrides.blockedTools ?? DEFAULT_CONFIG.blockedTools,
    sshOnlyMode: overrides.sshOnlyMode ?? DEFAULT_CONFIG.sshOnlyMode,
    llm: {
      ...DEFAULT_CONFIG.llm,
      enabled: true,
      debug: false,
      safetyEvaluator: {
        ...DEFAULT_CONFIG.llm.safetyEvaluator,
        enabled: true,
        actionMode: "permission",
      },
    },
  }
}

function makePermissionInput(overrides: Record<string, unknown> = {}) {
  return {
    id: "perm-1",
    action: "read",
    resources: [] as string[],
    sessionID: "s1",
    metadata: {},
    tool: { messageID: "msg-1", callID: "call-v2" },
    ...overrides,
  } as any
}

function makeAuditLogger() {
  return {
    log: async () => undefined,
    flush: () => {},
    destroy: () => {},
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Input sanitizer: alias-aware policy + V2 targets
// ─────────────────────────────────────────────────────────────────────────────

describe("V2 input sanitizer policy", () => {
  test("canonical blockedTools 'subagent' blocks legacy runtime 'task'", async () => {
    const { hook } = makeInputSanitizer({ ...DEFAULT_CONFIG, blockedTools: ["subagent"] })
    await expect(
      hook({ tool: "task", sessionID: "s1", callID: "c1" }, { args: {} }),
    ).rejects.toThrow("blocked by security policy")
  })

  test("legacy blockedTools 'task' blocks canonical runtime 'subagent'", async () => {
    const { hook } = makeInputSanitizer({ ...DEFAULT_CONFIG, blockedTools: ["task"] })
    await expect(
      hook({ tool: "subagent", sessionID: "s1", callID: "c1" }, { args: {} }),
    ).rejects.toThrow("blocked by security policy")
  })

  test("excludedTools canonical 'shell' skips legacy runtime 'bash'", async () => {
    const { hook } = makeInputSanitizer({ ...DEFAULT_CONFIG, excludedTools: ["shell"] })
    const output = { args: { command: `echo ${SECRET}` } }
    await hook({ tool: "bash", sessionID: "s1", callID: "c1" }, output)
    expect(output.args.command).toContain(SECRET)
  })

  test("sshOnlyMode recognizes V2 'shell' and still redacts remote command input", async () => {
    const { hook } = makeInputSanitizer({ ...DEFAULT_CONFIG, sshOnlyMode: true })
    const output = { args: { command: `ssh web-01 "echo ${SECRET}"` } }
    await hook({ tool: "shell", sessionID: "s1", callID: "c1" }, output)
    expect(output.args.command).not.toContain(SECRET)
    expect(output.args.command).toContain("[REDACTED]")
  })
})

describe("V2 input sanitizer file targets", () => {
  test("blocks V2 read `path` to a sensitive file", async () => {
    const { hook } = makeInputSanitizer(DEFAULT_CONFIG)
    await expect(
      hook({ tool: "read", sessionID: "s1", callID: "c1" }, { args: { path: "/project/.env" } }),
    ).rejects.toThrow("blocked by security policy")
  })

  test("blocks V2 write `path` to a sensitive file", async () => {
    const { hook } = makeInputSanitizer(DEFAULT_CONFIG)
    await expect(
      hook(
        { tool: "write", sessionID: "s1", callID: "c1" },
        { args: { path: "/project/.env", content: "FOO=bar" } },
      ),
    ).rejects.toThrow("blocked by security policy")
  })

  test("blocks a patch whose Move to destination is sensitive", async () => {
    const { hook } = makeInputSanitizer(DEFAULT_CONFIG)
    const patchText = [
      "*** Begin Patch",
      "*** Update File: /project/src/app.ts",
      "@@",
      "-old",
      "+new",
      "*** Move to: /project/.env",
      "*** End Patch",
    ].join("\n")
    await expect(
      hook({ tool: "patch", sessionID: "s1", callID: "c1" }, { args: { patchText } }),
    ).rejects.toThrow("blocked by security policy")
  })

  test("blocks a patch whose Add File target is sensitive", async () => {
    const { hook } = makeInputSanitizer(DEFAULT_CONFIG)
    const patchText = [
      "*** Begin Patch",
      "*** Add File: /project/.env",
      "+SECRET=value",
      "*** End Patch",
    ].join("\n")
    await expect(
      hook({ tool: "patch", sessionID: "s1", callID: "c1" }, { args: { patchText } }),
    ).rejects.toThrow("blocked by security policy")
  })

  test("patch redaction exemption requires every target (move included) to be exempt", async () => {
    const config = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["/project/src/config.ts"],
    }
    const { hook } = makeInputSanitizer(config)
    const patchText = [
      "*** Begin Patch",
      "*** Update File: /project/src/config.ts",
      "@@",
      "-old",
      `+API_KEY=${SECRET}`,
      "*** Move to: /project/src/random.ts",
      "*** End Patch",
    ].join("\n")
    const output = { args: { patchText } }
    await hook({ tool: "patch", sessionID: "s1", callID: "c1" }, output)
    expect(output.args.patchText).not.toContain(SECRET)
    expect(output.args.patchText).toContain("[REDACTED]")
  })

  test("patch redaction exemption applies when every target is exempt", async () => {
    const config = {
      ...DEFAULT_CONFIG,
      redactionExemptPaths: ["/project/src/config.ts", "/project/src/random.ts"],
    }
    const { hook } = makeInputSanitizer(config)
    const patchText = [
      "*** Begin Patch",
      "*** Update File: /project/src/config.ts",
      "@@",
      "-old",
      `+API_KEY=${SECRET}`,
      "*** Move to: /project/src/random.ts",
      "*** End Patch",
    ].join("\n")
    const output = { args: { patchText } }
    await hook({ tool: "patch", sessionID: "s1", callID: "c1" }, output)
    expect(output.args.patchText).toContain(SECRET)
    expect(output.args.patchText).not.toContain("[REDACTED]")
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Output redactor: V2 paths + shell alias
// ─────────────────────────────────────────────────────────────────────────────

describe("V2 output redactor", () => {
  test("read exemption honors V2 `path`", async () => {
    const config = { ...DEFAULT_CONFIG, redactionExemptPaths: ["/project/src/config.ts"] }
    const { hook } = makeOutputRedactor(config)
    const original = `API_KEY=${SECRET}\n`
    const output = { output: original, title: "Read config", metadata: {} }
    await hook(
      { tool: "read", sessionID: "s1", callID: "c1", args: { path: "/project/src/config.ts" } },
      output,
    )
    expect(output.output).toBe(original)
  })

  test("shell read exemption works for canonical 'shell'", async () => {
    const config = { ...DEFAULT_CONFIG, redactionExemptPaths: ["/project/src/config.ts"] }
    const { hook } = makeOutputRedactor(config)
    const original = `API_KEY=${SECRET}\n`
    const output = { output: original, title: "shell", metadata: {} }
    await hook(
      {
        tool: "shell",
        sessionID: "s1",
        callID: "c1",
        args: { command: "cat /project/src/config.ts" },
      },
      output,
    )
    expect(output.output).toBe(original)
  })

  test("excludedTools canonical 'shell' skips legacy runtime 'bash' output", async () => {
    const config = { ...DEFAULT_CONFIG, excludedTools: ["shell"] }
    const { hook } = makeOutputRedactor(config)
    const original = `API_KEY=${SECRET}\n`
    const output = { output: original, title: "bash", metadata: {} }
    await hook(
      { tool: "bash", sessionID: "s1", callID: "c1", args: { command: "cat secrets.txt" } },
      output,
    )
    expect(output.output).toBe(original)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// LLM tool matching + canonical defaults
// ─────────────────────────────────────────────────────────────────────────────

describe("V2 LLM tool matching", () => {
  test("default tool lists are V2-canonical", () => {
    expect(DEFAULT_CONFIG.llm.safetyEvaluator.tools).not.toContain("bash")
    expect(DEFAULT_CONFIG.llm.safetyEvaluator.tools).toContain("shell")
    expect(DEFAULT_CONFIG.llm.outputSanitizer.tools).not.toContain("bash")
    expect(DEFAULT_CONFIG.llm.outputSanitizer.tools).toContain("shell")
  })

  test("sanitizer matches legacy runtime 'bash' against canonical 'shell' config", () => {
    const config = {
      ...DEFAULT_CONFIG.llm,
      enabled: true,
      outputSanitizer: {
        ...DEFAULT_CONFIG.llm.outputSanitizer,
        enabled: true,
        tools: ["shell"],
      },
    }
    const sanitizer = new LlmSanitizer(config, new ProviderChain([makeProvider()]))
    expect(sanitizer.shouldSanitize("bash")).toBe(true)
    expect(sanitizer.shouldSanitize("shell")).toBe(true)
  })

  test("sanitizer matches canonical runtime 'shell' against legacy 'bash' config", () => {
    const config = {
      ...DEFAULT_CONFIG.llm,
      enabled: true,
      outputSanitizer: {
        ...DEFAULT_CONFIG.llm.outputSanitizer,
        enabled: true,
        tools: ["bash"],
      },
    }
    const sanitizer = new LlmSanitizer(config, new ProviderChain([makeProvider()]))
    expect(sanitizer.shouldSanitize("shell")).toBe(true)
  })

  test("safety evaluator matches both spellings; isBypassed accepts V2 'shell'", () => {
    const config = {
      ...DEFAULT_CONFIG.llm,
      safetyEvaluator: {
        ...DEFAULT_CONFIG.llm.safetyEvaluator,
        enabled: true,
        tools: ["shell"],
      },
    }
    const evaluator = new SafetyEvaluator(config, new ProviderChain([makeProvider()]))
    expect(evaluator.shouldEvaluate("bash")).toBe(true)
    expect(evaluator.shouldEvaluate("shell")).toBe(true)
    expect(evaluator.isBypassed("shell", { command: "ls -la" })).toBe(true)
  })

  test("safety evaluator isBypassed ignores non-shell actions", () => {
    const evaluator = new SafetyEvaluator(DEFAULT_CONFIG.llm, new ProviderChain([makeProvider()]))
    expect(evaluator.isBypassed("read", { command: "ls -la" })).toBe(false)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Permission handler: V2 action/resources/message
// ─────────────────────────────────────────────────────────────────────────────

describe("V2 permission handler", () => {
  test("uses V2 action and tool.callID for bypass + dedup", async () => {
    const config = makePermissionConfig()
    const evaluatedCalls = new Set<string>()
    let capturedArgs: Record<string, unknown> = {}
    const evaluator = {
      shouldEvaluate: () => true,
      isBypassed: (_tool: string, args: Record<string, unknown>) => {
        capturedArgs = args
        return true
      },
      evaluate: async () => {
        throw new Error("should not be called")
      },
    }
    const handler = createPermissionHandler({
      config,
      client: mockClient as any,
      safetyEvaluator: evaluator as any,
      evaluatedCalls,
      sessionAllowlist: new Set(),
      auditLogger: makeAuditLogger() as any,
      diagnosticLogger: null,
    })
    const output: { status: "ask" | "deny" | "allow"; message?: string } = { status: "ask" }

    await handler(
      makePermissionInput({
        action: "shell",
        metadata: { command: "ls -la" },
        resources: ["/project/src"],
      }),
      output,
    )

    expect(output.status).toBe("allow")
    expect(evaluatedCalls.has("call-v2")).toBe(true)
    expect(capturedArgs.command).toBe("ls -la")
    expect(capturedArgs.resources).toEqual(["/project/src"])
  })

  test("denies V2 write resources that hit blocked file paths without calling the LLM", async () => {
    const config = makePermissionConfig()
    let evaluationCalled = false
    const evaluator = {
      shouldEvaluate: () => true,
      isBypassed: () => false,
      evaluate: async () => {
        evaluationCalled = true
        throw new Error("should not be called")
      },
    }
    const handler = createPermissionHandler({
      config,
      client: mockClient as any,
      safetyEvaluator: evaluator as any,
      evaluatedCalls: new Set(),
      sessionAllowlist: new Set(),
      auditLogger: makeAuditLogger() as any,
      diagnosticLogger: null,
    })
    const output: { status: "ask" | "deny" | "allow"; message?: string } = { status: "ask" }

    await handler(
      makePermissionInput({ action: "write", resources: ["/project/.env"] }),
      output,
    )

    expect(output.status).toBe("deny")
    expect(output.message).toContain(".env")
    expect(evaluationCalled).toBe(false)
  })

  test("denies V2 read resources that hit blocked file paths", async () => {
    const config = makePermissionConfig()
    const handler = createPermissionHandler({
      config,
      client: mockClient as any,
      safetyEvaluator: {
        shouldEvaluate: () => true,
        isBypassed: () => false,
        evaluate: async () => {
          throw new Error("should not be called")
        },
      } as any,
      evaluatedCalls: new Set(),
      sessionAllowlist: new Set(),
      auditLogger: makeAuditLogger() as any,
      diagnosticLogger: null,
    })
    const output: { status: "ask" | "deny" | "allow"; message?: string } = { status: "ask" }

    await handler(
      makePermissionInput({ action: "read", resources: ["/project/.env"] }),
      output,
    )

    expect(output.status).toBe("deny")
    expect(output.message).toContain(".env")
  })

  test("blockedTools are alias-aware for V2 actions", async () => {
    const config = makePermissionConfig({ blockedTools: ["subagent"] })
    const handler = createPermissionHandler({
      config,
      client: mockClient as any,
      safetyEvaluator: {
        shouldEvaluate: () => true,
        isBypassed: () => false,
        evaluate: async () => {
          throw new Error("should not be called")
        },
      } as any,
      evaluatedCalls: new Set(),
      sessionAllowlist: new Set(),
      auditLogger: makeAuditLogger() as any,
      diagnosticLogger: null,
    })
    const output: { status: "ask" | "deny" | "allow"; message?: string } = { status: "ask" }

    await handler(makePermissionInput({ action: "task" }), output)

    expect(output.status).toBe("deny")
    expect(output.message).toContain("task")
    expect(output.message).toContain("blocked by security policy")
  })

  test("denial message is populated on safety blocks", async () => {
    const config = makePermissionConfig()
    const handler = createPermissionHandler({
      config,
      client: mockClient as any,
      safetyEvaluator: {
        shouldEvaluate: () => true,
        isBypassed: () => false,
        evaluate: async () => ({
          safe: false,
          riskLevel: "critical",
          riskDimensions: ["destruction"],
          explanation: "recursive delete",
          suggestedAlternative: "",
          recommendation: "block",
        }),
      } as any,
      evaluatedCalls: new Set(),
      sessionAllowlist: new Set(),
      auditLogger: makeAuditLogger() as any,
      diagnosticLogger: null,
    })
    const output: { status: "ask" | "deny" | "allow"; message?: string } = { status: "ask" }

    await handler(
      makePermissionInput({ action: "shell", metadata: { command: "rm -rf /" } }),
      output,
    )

    expect(output.status).toBe("deny")
    expect(output.message).toContain("Command denied")
    expect(output.message).toContain("recursive delete")
  })

  test("sshOnlyMode treats V2 'shell' as the remote-capable action", async () => {
    const config = makePermissionConfig({ sshOnlyMode: true })
    let evaluated = false
    const handler = createPermissionHandler({
      config,
      client: mockClient as any,
      safetyEvaluator: {
        shouldEvaluate: () => true,
        isBypassed: () => true,
        evaluate: async () => {
          evaluated = true
          throw new Error("should not be called")
        },
      } as any,
      evaluatedCalls: new Set(),
      sessionAllowlist: new Set(),
      auditLogger: makeAuditLogger() as any,
      diagnosticLogger: null,
    })

    const remoteOutput: { status: "ask" | "deny" | "allow"; message?: string } = { status: "ask" }
    await handler(
      makePermissionInput({
        action: "shell",
        metadata: { command: 'ssh web-01 "ls"' },
      }),
      remoteOutput,
    )
    expect(remoteOutput.status).toBe("allow")

    const localOutput: { status: "ask" | "deny" | "allow"; message?: string } = { status: "ask" }
    await handler(
      makePermissionInput({
        action: "shell",
        metadata: { command: "ls -la" },
      }),
      localOutput,
    )
    expect(localOutput.status).toBe("ask")
    expect(evaluated).toBe(false)
  })
})
