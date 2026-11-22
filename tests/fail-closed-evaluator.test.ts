import { describe, test, expect, mock } from "bun:test"
import { createDetectionEngine } from "../src/detection/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import { SessionStats } from "../src/audit/session-stats.js"
import { createInputSanitizer } from "../src/hooks/input-sanitizer.js"
import { createOutputRedactor } from "../src/hooks/output-redactor.js"
import { createPermissionHandler } from "../src/hooks/permission-handler.js"
import { SafetyEvaluator } from "../src/llm/safety-evaluator.js"
import { ProviderChain } from "../src/llm/provider-chain.js"
import { ProviderOverloadError } from "../src/llm/request-queue.js"
import { SHELL_SEQUENCE_BLOCK_MESSAGE } from "../src/utils/shell-sequence.js"
import { SHELL_PRECHECK_UNAVAILABLE_MESSAGE, SIMPLIFY_SHELL_MESSAGE } from "../src/llm/shell-complexity.js"
import type {
  LlmProviderConfig,
  PluginClient,
  SecurityGuardConfig,
  ToastState,
  WrittenFileMetadata,
} from "../src/types.js"

const mockClient: PluginClient = {
  app: { log: async () => undefined },
  tui: { showToast: async () => undefined },
  session: { prompt: async () => undefined },
}

function makeAuditLogger() {
  return { log: mock(async () => {}), flush: () => {}, destroy: () => {} }
}

function makeConfig(overrides: Record<string, unknown> = {}): SecurityGuardConfig {
  const base = { ...DEFAULT_CONFIG, ...overrides } as SecurityGuardConfig
  const llmOverrides = overrides.llm as Record<string, unknown> | undefined
  if (llmOverrides) {
    base.llm = { ...DEFAULT_CONFIG.llm, ...llmOverrides } as SecurityGuardConfig["llm"]
    const se = llmOverrides.safetyEvaluator as Record<string, unknown> | undefined
    if (se) {
      base.llm.safetyEvaluator = {
        ...DEFAULT_CONFIG.llm.safetyEvaluator,
        ...se,
      } as SecurityGuardConfig["llm"]["safetyEvaluator"]
    }
    const os = llmOverrides.outputSanitizer as Record<string, unknown> | undefined
    if (os) {
      base.llm.outputSanitizer = {
        ...DEFAULT_CONFIG.llm.outputSanitizer,
        ...os,
      } as SecurityGuardConfig["llm"]["outputSanitizer"]
    }
  }
  return base
}

function makeInputDeps(config: SecurityGuardConfig, overrides: Record<string, unknown> = {}) {
  const toastState: ToastState = { lastToastTime: 0, minInterval: 0 }
  return {
    engine: createDetectionEngine(config),
    config,
    auditLogger: makeAuditLogger() as never,
    projectDir: "/workspace",
    client: mockClient,
    safetyEvaluator: null,
    sessionStats: new SessionStats("test"),
    toastState,
    sessionAllowlist: new Set<string>(),
    evaluatedCalls: new Set<string>(),
    diagnosticLogger: null,
    writtenFileRegistry: new Map<string, WrittenFileMetadata>(),
    ...overrides,
  }
}

function makeEvaluator(overrides: Record<string, unknown> = {}) {
  return {
    shouldEvaluate: mock(() => true),
    isBypassed: mock(() => false),
    evaluate: mock(async () => ({
      safe: false,
      riskLevel: "critical",
      riskDimensions: [],
      explanation: "risk",
      suggestedAlternative: "",
      recommendation: "block",
    })),
    evaluateFileExecution: mock(async () => ({
      safe: false,
      riskLevel: "critical",
      riskDimensions: [],
      explanation: "risk",
      suggestedAlternative: "",
      recommendation: "block",
    })),
    ...overrides,
  }
}

const validSafeVerdict = {
  safe: true,
  riskLevel: "low",
  riskDimensions: [],
  explanation: "safe",
  suggestedAlternative: "",
  recommendation: "allow",
}

describe("static shell sequence enforcement", () => {
  test.each(["block", "warn", "permission"] as const)(
    "blocks before either evaluator or deduplication in %s mode",
    async (actionMode) => {
      const config = makeConfig({ llm: { enabled: true, safetyEvaluator: { actionMode } } })
      const evaluator = makeEvaluator()
      const deps = makeInputDeps(config, {
        safetyEvaluator: evaluator,
        evaluatedCalls: new Set(["known-call"]),
      })
      const hook = createInputSanitizer(deps)
      await expect(hook(
        { tool: "shell", sessionID: "s1", callID: "known-call" },
        { args: { command: "git status; git diff" } },
      )).rejects.toThrow(SHELL_SEQUENCE_BLOCK_MESSAGE)
      expect(evaluator.shouldEvaluate).not.toHaveBeenCalled()
      expect(evaluator.evaluate).not.toHaveBeenCalled()
      expect(evaluator.evaluateFileExecution).not.toHaveBeenCalled()
    },
  )

  test("blocks the legacy alias with the LLM disabled but does not block a pipeline", async () => {
    const hook = createInputSanitizer(makeInputDeps(makeConfig({ llm: { enabled: false } })))
    const input = { tool: "bash", sessionID: "s1", callID: "c1" }
    await expect(hook(input, { args: { command: "git status\ngit diff" } }))
      .rejects.toThrow(SHELL_SEQUENCE_BLOCK_MESSAGE)
    await expect(hook(input, { args: { command: "git diff |\nwc -l" } }))
      .resolves.toBeUndefined()
  })

  test("permission mode denies a batch in any shell resource before the evaluator", async () => {
    const config = makeConfig({ llm: { enabled: true, safetyEvaluator: { actionMode: "permission" } } })
    const evaluator = makeEvaluator()
    const hook = createPermissionHandler(makeInputDeps(config, { safetyEvaluator: evaluator }))
    const output: { status: "ask" | "deny"; message?: string } = { status: "ask" }
    await hook({
      id: "p1", sessionID: "s1", action: "shell",
      metadata: { command: "git status" },
      resources: ["git status", "git status\ngit diff"],
    }, output)
    expect(output).toEqual({ status: "deny", message: SHELL_SEQUENCE_BLOCK_MESSAGE })
    expect(evaluator.shouldEvaluate).not.toHaveBeenCalled()
    expect(evaluator.evaluate).not.toHaveBeenCalled()
  })
})

describe("SafetyEvaluator failure signal", () => {
  function makeLlmConfig(
    overrides: Record<string, unknown> = {},
  ): SecurityGuardConfig["llm"] {
    return {
      ...DEFAULT_CONFIG.llm,
      enabled: true,
      ...overrides,
      safetyEvaluator: {
        ...DEFAULT_CONFIG.llm.safetyEvaluator,
        ...((overrides.safetyEvaluator || {}) as Record<string, unknown>),
      },
    } as SecurityGuardConfig["llm"]
  }

  function makeProvider(): LlmProviderConfig {
    return {
      name: "test",
      cooldown: 0,
      baseUrl: "http://localhost:11434/v1",
      model: "test-model",
      apiKey: "",
      timeout: 5000,
      temperature: 0,
      headers: {},
      healthCheckPath: "/models",
      completionsPath: "/chat/completions",
    }
  }

  function makeComplexityEvaluator(config = makeLlmConfig({
    safetyEvaluator: { complexityPrecheck: { enabled: true } },
  }), response = '{"decision":"continue"}') {
    const chain = new ProviderChain([makeProvider()])
    const precheck = mock<ProviderChain["callValidated"]>(async (_messages, validate) => validate(response))
    const safety = mock<ProviderChain["call"]>(async () => JSON.stringify(validSafeVerdict))
    chain.callValidated = precheck
    chain.call = safety
    return { evaluator: new SafetyEvaluator(config, chain), precheck, safety }
  }

  test("default-off and explicitly disabled modes do not consult the precheck", async () => {
    for (const config of [
      makeLlmConfig(),
      makeLlmConfig({ enabled: false, safetyEvaluator: { complexityPrecheck: { enabled: true } } }),
      makeLlmConfig({ safetyEvaluator: { enabled: false, complexityPrecheck: { enabled: true } } }),
    ]) {
      const { evaluator, precheck } = makeComplexityEvaluator(config)
      expect(await evaluator.precheckComplexity("shell", { command: "(git status)" })).toBeUndefined()
      expect(precheck).not.toHaveBeenCalled()
    }
  })

  test("static blocks, simple commands, and pipelines do not call the precheck", async () => {
    const { evaluator, precheck } = makeComplexityEvaluator()
    expect((await evaluator.dryRun("bash", { command: "git status; git diff" })).staticBlock).toBe("shell-sequence")
    for (const command of [
      "git status",
      "git diff | wc -l",
      "git status && git diff",
      "printf '%s' '$(text); data'",
      "cat <<'EOF'\n(git status)\nEOF\n",
    ]) {
      expect(await evaluator.precheckComplexity("shell", { command })).toBeUndefined()
    }
    expect(precheck).not.toHaveBeenCalled()
  })

  test("continue sends only the command to the precheck and still requires full evaluation", async () => {
    const { evaluator, precheck, safety } = makeComplexityEvaluator()
    const command = 'printf "%s" "$(git status --short)"'
    evaluator.isBypassed = mock(() => true)
    const result = await evaluator.dryRun("shell", { command, description: "private task context" })
    expect(result.recommendation).toBe("allow")
    expect(precheck).toHaveBeenCalledTimes(1)
    const [messages] = precheck.mock.calls[0]!
    expect(messages).toHaveLength(2)
    expect(messages[1]).toEqual({ role: "user", content: JSON.stringify({ command }) })
    expect(safety).toHaveBeenCalledTimes(1)
    expect(evaluator.isBypassed).not.toHaveBeenCalled()
    expect(JSON.stringify(safety.mock.calls[0])).not.toContain("conditional-chain")
  })

  test("candidate selection depends on shell syntax, not the command's risk", async () => {
    const { evaluator, precheck, safety } = makeComplexityEvaluator()
    await evaluator.dryRun("shell", { command: "rm -rf /" })
    expect(precheck).not.toHaveBeenCalled()
    expect(safety).toHaveBeenCalledTimes(1)

    for (const command of ["(printf ok; git status)", "(printf ok; rm -rf /)"]) {
      expect(await evaluator.precheckComplexity("shell", { command })).toBe("continue")
    }
    expect(precheck).toHaveBeenCalledTimes(2)
  })

  test("a provider outage is distinct from a simplification verdict", async () => {
    const { evaluator, precheck, safety } = makeComplexityEvaluator()
    precheck.mockRejectedValueOnce(new Error("provider unavailable"))
    const result = await evaluator.dryRun("shell", { command: "(git status)" })
    expect(result).toMatchObject({
      recommendation: "block",
      evaluationFailed: true,
      complexityPrecheck: "unavailable",
    })
    expect(safety).not.toHaveBeenCalled()
  })

  test("valid simplification in warn mode vetoes before either safety request", async () => {
    const config = makeConfig({
      llm: { enabled: true, safetyEvaluator: { actionMode: "warn", complexityPrecheck: { enabled: true } } },
    })
    const { evaluator, precheck, safety } = makeComplexityEvaluator(config.llm,
      '{"decision":"simplify","reason":"group"}')
    const fileSafety = mock(evaluator.evaluateFileExecution.bind(evaluator))
    evaluator.evaluateFileExecution = fileSafety
    const hook = createInputSanitizer(makeInputDeps(config, { safetyEvaluator: evaluator }))
    await expect(hook(
      { tool: "shell", sessionID: "s1", callID: "c1" },
      { args: { command: "(git status; git diff)" } },
    )).rejects.toThrow(SIMPLIFY_SHELL_MESSAGE)
    expect(precheck).toHaveBeenCalledTimes(1)
    expect(safety).not.toHaveBeenCalled()
    expect(fileSafety).not.toHaveBeenCalled()
  })

  test.each([
    '{"decision":"allow"}',
    '{"decision":"continue","reason":"group"}',
    '{"decision":"simplify","reason":"substitution"}',
    '{"decision":"simplify","reason":"dangerous"}',
    'not JSON',
  ])("invalid precheck %s fails closed without calling full evaluation", async (response) => {
    const config = makeConfig({
      llm: { enabled: true, safetyEvaluator: { actionMode: "permission", complexityPrecheck: { enabled: true } } },
    })
    const { evaluator, safety } = makeComplexityEvaluator(config.llm, response)
    const hook = createPermissionHandler(makeInputDeps(config, { safetyEvaluator: evaluator }))
    const output: { status: "ask" | "deny"; message?: string } = { status: "ask" }
    await hook({ id: "p1", sessionID: "s1", action: "shell", resources: ["(git status)"] }, output)
    expect(output).toEqual({ status: "deny", message: SHELL_PRECHECK_UNAVAILABLE_MESSAGE })
    expect(safety).not.toHaveBeenCalled()
  })

  test("T7.5 harness fixture is blocked statically without calling the provider", async () => {
    const suite = await Bun.file(new URL("../scripts/llm-harness-tests.json", import.meta.url)).json()
    const fixture = suite.tests.find((entry: { id: string }) => entry.id === "T7.5")
    expect(fixture.command.split("\n")).toHaveLength(3)
    const chain = new ProviderChain([makeProvider()])
    const call = mock(async () => JSON.stringify(validSafeVerdict))
    chain.call = call
    const evaluator = new SafetyEvaluator(makeLlmConfig(), chain)
    const result = await evaluator.dryRun("bash", { command: fixture.command })
    expect(result.recommendation).toBe("block")
    expect(result.staticBlock).toBe("shell-sequence")
    expect(result.evaluationFailed).toBeUndefined()
    expect(call).not.toHaveBeenCalled()
  })

  test("LLM transport failure is marked evaluationFailed", async () => {
    const chain = new ProviderChain([makeProvider()])
    chain.call = mock(async () => {
      throw new Error("connection refused")
    })
    const evaluator = new SafetyEvaluator(makeLlmConfig(), chain)

    const result = await evaluator.evaluate("shell", { command: "rm -rf /" })

    expect(result.recommendation).toBe("block")
    expect(result.evaluationFailed).toBe(true)
  })

  test("unparseable response is marked evaluationFailed", async () => {
    const chain = new ProviderChain([makeProvider()])
    chain.call = mock(async () => "not json at all")
    const evaluator = new SafetyEvaluator(makeLlmConfig(), chain)

    const result = await evaluator.evaluate("shell", { command: "ls" })

    expect(result.recommendation).toBe("block")
    expect(result.evaluationFailed).toBe(true)
  })

  test("garbage riskLevel is marked evaluationFailed instead of failing open", async () => {
    const chain = new ProviderChain([makeProvider()])
    chain.call = mock(async () => JSON.stringify({
      safe: true,
      riskLevel: "banana",
      riskDimensions: [],
      explanation: "looks safe",
      suggestedAlternative: "",
      recommendation: "allow",
    }))
    const evaluator = new SafetyEvaluator(makeLlmConfig(), chain)

    const result = await evaluator.evaluate("shell", { command: "echo hi" })

    expect(result.recommendation).toBe("block")
    expect(result.evaluationFailed).toBe(true)
  })

  test("genuine model verdict has no evaluationFailed marker", async () => {
    const chain = new ProviderChain([makeProvider()])
    chain.call = mock(async () => JSON.stringify({
      safe: false,
      riskLevel: "critical",
      riskDimensions: ["destruction"],
      explanation: "recursive delete",
      suggestedAlternative: "",
      recommendation: "block",
    }))
    const evaluator = new SafetyEvaluator(makeLlmConfig(), chain)

    const result = await evaluator.evaluate("shell", { command: "rm -rf /" })

    expect(result.recommendation).toBe("block")
    expect(result.evaluationFailed).toBeUndefined()
  })

  test("a model block verdict is not downgraded by a contradictory low riskLevel", async () => {
    const chain = new ProviderChain([makeProvider()])
    chain.call = mock(async () => JSON.stringify({
      safe: false,
      riskLevel: "low",
      riskDimensions: [],
      explanation: "model still wants a block",
      suggestedAlternative: "",
      recommendation: "block",
    }))
    const evaluator = new SafetyEvaluator(makeLlmConfig(), chain)

    const result = await evaluator.evaluate("shell", { command: "rm -rf /" })

    expect(result.recommendation).toBe("block")
    expect(result.evaluationFailed).toBeUndefined()
  })

  test("invalid recommendation is marked evaluationFailed instead of defaulting to allow", async () => {
    const chain = new ProviderChain([makeProvider()])
    chain.call = mock(async () => JSON.stringify({
      safe: true,
      riskLevel: "none",
      riskDimensions: [],
      explanation: "garbage recommendation",
      suggestedAlternative: "",
      recommendation: "definitely-fine",
    }))
    const evaluator = new SafetyEvaluator(makeLlmConfig(), chain)

    const result = await evaluator.evaluate("shell", { command: "echo hi" })

    expect(result.recommendation).toBe("block")
    expect(result.evaluationFailed).toBe(true)
  })
})

describe("input-sanitizer evaluator availability", () => {
  test("queue overload blocks with actionable copy even in warn mode", async () => {
    const config = makeConfig({ llm: { enabled: true,
      safetyEvaluator: { enabled: true, actionMode: "warn", tools: ["read"] },
    } })
    const evaluator = makeEvaluator({ evaluate: mock(async () => ({
      ...validSafeVerdict, safe: false, riskLevel: "critical", recommendation: "block",
      evaluationFailed: true, providerOverloaded: true,
    })) })
    const hook = createInputSanitizer(makeInputDeps(config, { safetyEvaluator: evaluator }) as never)
    await expect(hook({ tool: "read", sessionID: "s1", callID: "overload" },
      { args: { path: "/workspace/src/app.ts" } })).rejects.toThrow("overloaded by concurrent requests")
  })

  test("warn mode still blocks an evaluator outage", async () => {
    const config = makeConfig({
      llm: {
        enabled: true,
        safetyEvaluator: { enabled: true, actionMode: "warn", tools: ["read"] },
      },
    })
    const evaluator = makeEvaluator({
      evaluate: mock(async () => ({
        ...validSafeVerdict,
        safe: false,
        riskLevel: "critical",
        recommendation: "block",
        explanation: "LLM unreachable — blocking for safety",
        evaluationFailed: true,
      })),
    })
    const hook = createInputSanitizer(makeInputDeps(config, { safetyEvaluator: evaluator }) as never)

    await expect(
      hook(
        { tool: "read", sessionID: "s1", callID: "c1" },
        { args: { path: "/workspace/src/app.ts" } },
      ),
    ).rejects.toThrow("safety evaluator unavailable")
  })

  test("warn mode may downgrade a genuine model block verdict", async () => {
    const config = makeConfig({
      llm: {
        enabled: true,
        safetyEvaluator: { enabled: true, actionMode: "warn", tools: ["read"] },
      },
    })
    const evaluator = makeEvaluator({
      evaluate: mock(async () => ({
        safe: false,
        riskLevel: "critical",
        riskDimensions: ["destruction"],
        explanation: "genuine risk",
        suggestedAlternative: "",
        recommendation: "block",
      })),
    })
    const hook = createInputSanitizer(makeInputDeps(config, { safetyEvaluator: evaluator }) as never)

    await hook(
      { tool: "read", sessionID: "s1", callID: "c1" },
      { args: { path: "/workspace/src/app.ts" } },
    )
  })

  test("enabled but null safety evaluator blocks regardless of actionMode", async () => {
    for (const actionMode of ["block", "warn", "permission"] as const) {
      const config = makeConfig({
        llm: {
          enabled: true,
          safetyEvaluator: { enabled: true, actionMode, tools: ["read"] },
        },
      })
      const hook = createInputSanitizer(makeInputDeps(config, { safetyEvaluator: null }) as never)

      await expect(
        hook(
          { tool: "read", sessionID: "s1", callID: "c1" },
          { args: { path: "/workspace/src/app.ts" } },
        ),
      ).rejects.toThrow("safety evaluator unavailable")
    }
  })

  test("explicitly disabled LLM does not block on a null evaluator", async () => {
    const config = makeConfig({
      llm: {
        enabled: false,
        safetyEvaluator: { enabled: false, actionMode: "warn", tools: ["read"] },
      },
    })
    const hook = createInputSanitizer(makeInputDeps(config, { safetyEvaluator: null }) as never)

    await hook(
      { tool: "read", sessionID: "s1", callID: "c1" },
      { args: { path: "/workspace/src/app.ts" } },
    )
  })

  test("individually disabled safety component does not block on a null evaluator", async () => {
    const config = makeConfig({
      llm: {
        enabled: true,
        safetyEvaluator: { enabled: false, actionMode: "warn", tools: ["read"] },
      },
    })
    const hook = createInputSanitizer(makeInputDeps(config, { safetyEvaluator: null }) as never)

    await hook(
      { tool: "read", sessionID: "s1", callID: "c1" },
      { args: { path: "/workspace/src/app.ts" } },
    )
  })
})

describe("permission-handler deterministic and failure paths", () => {
  function makePermissionInput(overrides: Record<string, unknown> = {}) {
    return {
      id: "perm-1",
      sessionID: "s1",
      callID: "call-1",
      ...overrides,
    }
  }

  test("blockedTools is denied before shouldEvaluate can skip the action", async () => {
    const config = makeConfig({
      blockedTools: ["webfetch"],
      llm: {
        enabled: true,
        safetyEvaluator: { enabled: true, actionMode: "permission", tools: ["shell"] },
      },
    })
    const evaluator = makeEvaluator({
      shouldEvaluate: mock(() => false),
      evaluate: mock(async () => {
        throw new Error("should not be called")
      }),
    })
    const handler = createPermissionHandler({
      config,
      client: mockClient,
      projectDir: "/workspace",
      safetyEvaluator: evaluator as never,
      evaluatedCalls: new Set<string>(),
      sessionAllowlist: new Set<string>(),
      auditLogger: makeAuditLogger() as never,
      diagnosticLogger: null,
    })

    const output = { status: "ask" as "ask" | "deny" | "allow" }
    await handler(makePermissionInput({ action: "webfetch", resources: [] }) as never, output)

    expect(output.status).toBe("deny")
    expect(evaluator.evaluate).not.toHaveBeenCalled()
  })

  test("deterministic blockedTools deny does not depend on an LLM evaluator existing", async () => {
    const config = makeConfig({
      blockedTools: ["webfetch"],
      llm: {
        enabled: false,
        safetyEvaluator: { enabled: false, actionMode: "permission" },
      },
    })
    const handler = createPermissionHandler({
      config,
      client: mockClient,
      projectDir: "/workspace",
      safetyEvaluator: null,
      evaluatedCalls: new Set<string>(),
      sessionAllowlist: new Set<string>(),
      auditLogger: makeAuditLogger() as never,
      diagnosticLogger: null,
    })

    const output = { status: "ask" as "ask" | "deny" | "allow" }
    await handler(makePermissionInput({ action: "webfetch", resources: [] }) as never, output)

    expect(output.status).toBe("deny")
  })

  test("shell resources are parsed as raw commands, not treated as a path", async () => {
    const config = makeConfig({
      blockedFilePaths: ["**/secrets.txt"],
      llm: {
        enabled: true,
        safetyEvaluator: { enabled: true, actionMode: "permission", tools: ["shell"] },
      },
    })
    const evaluator = makeEvaluator({
      evaluate: mock(async () => {
        throw new Error("should not be called")
      }),
    })
    const handler = createPermissionHandler({
      config,
      client: mockClient,
      projectDir: "/workspace",
      safetyEvaluator: evaluator as never,
      evaluatedCalls: new Set<string>(),
      sessionAllowlist: new Set<string>(),
      auditLogger: makeAuditLogger() as never,
      diagnosticLogger: null,
    })

    const output = { status: "ask" as "ask" | "deny" | "allow" }
    await handler(
      makePermissionInput({
        action: "shell",
        resources: ["cat secrets.txt"],
        metadata: {},
      }) as never,
      output,
    )

    expect(output.status).toBe("deny")
    expect(evaluator.evaluate).not.toHaveBeenCalled()
  })

  test("shell write redirection resources are checked against writeProtectedPaths", async () => {
    const config = makeConfig({
      writeProtectedPaths: ["**/protected.txt"],
      llm: {
        enabled: true,
        safetyEvaluator: { enabled: true, actionMode: "permission", tools: ["shell"] },
      },
    })
    const handler = createPermissionHandler({
      config,
      client: mockClient,
      projectDir: "/workspace",
      safetyEvaluator: makeEvaluator() as never,
      evaluatedCalls: new Set<string>(),
      sessionAllowlist: new Set<string>(),
      auditLogger: makeAuditLogger() as never,
      diagnosticLogger: null,
    })

    const output = { status: "ask" as "ask" | "deny" | "allow" }
    await handler(
      makePermissionInput({
        action: "shell",
        resources: ["echo hi > protected.txt"],
        metadata: {},
      }) as never,
      output,
    )

    expect(output.status).toBe("deny")
  })

  test("relative file resources resolve against projectDir", async () => {
    const config = makeConfig({
      blockedFilePaths: ["/workspace/nested/**"],
      llm: {
        enabled: true,
        safetyEvaluator: { enabled: true, actionMode: "permission", tools: ["read"] },
      },
    })
    const handler = createPermissionHandler({
      config,
      client: mockClient,
      projectDir: "/workspace",
      safetyEvaluator: makeEvaluator() as never,
      evaluatedCalls: new Set<string>(),
      sessionAllowlist: new Set<string>(),
      auditLogger: makeAuditLogger() as never,
      diagnosticLogger: null,
    })

    const output = { status: "ask" as "ask" | "deny" | "allow" }
    await handler(
      makePermissionInput({
        action: "read",
        resources: ["nested/secret.txt"],
        metadata: {},
      }) as never,
      output,
    )

    expect(output.status).toBe("deny")
  })

  test("sshOnlyMode sees the raw command in resources instead of skipping evaluation", async () => {
    const config = makeConfig({
      sshOnlyMode: true,
      blockedFilePaths: ["/etc/passwd"],
      llm: {
        enabled: true,
        safetyEvaluator: { enabled: true, actionMode: "permission", tools: ["shell"] },
      },
    })
    const evaluator = makeEvaluator({
      evaluate: mock(async () => {
        throw new Error("should not be called")
      }),
    })
    const handler = createPermissionHandler({
      config,
      client: mockClient,
      projectDir: "/workspace",
      safetyEvaluator: evaluator as never,
      evaluatedCalls: new Set<string>(),
      sessionAllowlist: new Set<string>(),
      auditLogger: makeAuditLogger() as never,
      diagnosticLogger: null,
    })

    const output = { status: "ask" as "ask" | "deny" | "allow" }
    await handler(
      makePermissionInput({
        action: "shell",
        resources: ["ssh web-1 cat /etc/passwd"],
        metadata: {},
      }) as never,
      output,
    )

    expect(output.status).toBe("deny")
    expect(evaluator.evaluate).not.toHaveBeenCalled()
  })

  test("subagent resources (agent IDs) are not treated as file paths", async () => {
    const config = makeConfig({
      blockedFilePaths: ["**/general"],
      llm: {
        enabled: true,
        safetyEvaluator: { enabled: true, actionMode: "permission", tools: ["subagent"] },
      },
    })
    const evaluator = makeEvaluator({
      evaluate: mock(async () => validSafeVerdict),
    })
    const handler = createPermissionHandler({
      config,
      client: mockClient,
      projectDir: "/workspace",
      safetyEvaluator: evaluator as never,
      evaluatedCalls: new Set<string>(),
      sessionAllowlist: new Set<string>(),
      auditLogger: makeAuditLogger() as never,
      diagnosticLogger: null,
    })

    const output = { status: "ask" as "ask" | "deny" | "allow" }
    await handler(
      makePermissionInput({
        action: "subagent",
        resources: ["general"],
        metadata: {},
      }) as never,
      output,
    )

    expect(output.status).toBe("allow")
    expect(evaluator.evaluate).toHaveBeenCalled()
  })

  test("queue overload denies permission with an explicit overload message", async () => {
    const config = makeConfig({ llm: { enabled: true,
      safetyEvaluator: { enabled: true, actionMode: "permission", tools: ["shell"] },
    } })
    const evaluator = makeEvaluator({ evaluate: mock(async () => ({
      ...validSafeVerdict, safe: false, riskLevel: "critical", recommendation: "block",
      evaluationFailed: true, providerOverloaded: true,
    })) })
    const handler = createPermissionHandler({
      config, client: mockClient, projectDir: "/workspace", safetyEvaluator: evaluator as never,
      evaluatedCalls: new Set<string>(), sessionAllowlist: new Set<string>(),
      auditLogger: makeAuditLogger() as never, diagnosticLogger: null,
    })
    const output = { status: "ask" as "ask" | "deny" | "allow", message: "" }
    await handler(makePermissionInput({ action: "shell", resources: ["echo hi"], metadata: {} }) as never, output)
    expect(output.status).toBe("deny")
    expect(output.message).toContain("overloaded by concurrent requests")
  })

  test("evaluator failure denies instead of prompting the user", async () => {
    const config = makeConfig({
      llm: {
        enabled: true,
        safetyEvaluator: { enabled: true, actionMode: "permission", tools: ["shell"] },
      },
    })
    const evaluator = makeEvaluator({
      evaluate: mock(async () => ({
        safe: false,
        riskLevel: "critical",
        riskDimensions: [],
        explanation: "LLM unreachable — blocking for safety",
        suggestedAlternative: "",
        recommendation: "block",
        evaluationFailed: true,
      })),
    })
    const handler = createPermissionHandler({
      config,
      client: mockClient,
      projectDir: "/workspace",
      safetyEvaluator: evaluator as never,
      evaluatedCalls: new Set<string>(),
      sessionAllowlist: new Set<string>(),
      auditLogger: makeAuditLogger() as never,
      diagnosticLogger: null,
    })

    const output = { status: "ask" as "ask" | "deny" | "allow" }
    await handler(
      makePermissionInput({ action: "shell", resources: ["echo hi"], metadata: {} }) as never,
      output,
    )

    expect(output.status).toBe("deny")
    expect(output.message).toContain("unavailable")
  })
})

describe("output-redactor sanitizer availability", () => {
  function makeOutputDeps(config: SecurityGuardConfig, overrides: Record<string, unknown> = {}) {
    return {
      engine: createDetectionEngine(config),
      config,
      auditLogger: makeAuditLogger() as never,
      projectDir: "/workspace",
      client: mockClient,
      outputTriage: null,
      outputTextTriage: null,
      diagnosticLogger: null,
      sessionStats: new SessionStats("test"),
      toastState: { lastToastTime: 0, minInterval: 0 } as ToastState,
      ...overrides,
    }
  }

  test("queue overload withholds output and reports overload instead of raw content", async () => {
    const config = makeConfig({ llm: { enabled: true,
      outputSanitizer: { enabled: true, tools: ["read"], actionMode: "warn" },
    } })
    const sanitizer = { shouldSanitize: () => true, isAvailable: () => true,
      sanitize: async () => { throw new ProviderOverloadError() },
    }
    const hook = createOutputRedactor(makeOutputDeps(config, { llmSanitizer: sanitizer }) as never)
    const output = { output: "original output", title: "", metadata: {} }
    await hook({ tool: "read", sessionID: "s1", callID: "overload" }, output)
    expect(output.output).toContain("[BLOCKED]")
    expect(output.output).toContain("overloaded by concurrent requests")
    expect(output.output).not.toContain("original output")
  })

  test("enabled but null output sanitizer withholds output", async () => {
    const config = makeConfig({
      llm: {
        enabled: true,
        outputSanitizer: { enabled: true, tools: ["read"], actionMode: "redact" },
      },
    })
    const hook = createOutputRedactor(makeOutputDeps(config, { llmSanitizer: null }) as never)

    const output = { output: "clean output", title: "", metadata: {} }
    await hook({ tool: "read", sessionID: "s1", callID: "c1" }, output)

    expect(output.output.startsWith("[BLOCKED]")).toBe(true)
  })

  test("explicitly disabled LLM does not block on a null sanitizer", async () => {
    const config = makeConfig({
      llm: {
        enabled: false,
        outputSanitizer: { enabled: true, tools: ["read"], actionMode: "redact" },
      },
    })
    const hook = createOutputRedactor(makeOutputDeps(config, { llmSanitizer: null }) as never)

    const output = { output: "clean output", title: "", metadata: {} }
    await hook({ tool: "read", sessionID: "s1", callID: "c1" }, output)

    expect(output.output).toBe("clean output")
  })

  test("individually disabled output sanitizer does not block on a null instance", async () => {
    const config = makeConfig({
      llm: {
        enabled: true,
        outputSanitizer: { enabled: false, tools: ["read"], actionMode: "redact" },
      },
    })
    const hook = createOutputRedactor(makeOutputDeps(config, { llmSanitizer: null }) as never)

    const output = { output: "clean output", title: "", metadata: {} }
    await hook({ tool: "read", sessionID: "s1", callID: "c1" }, output)

    expect(output.output).toBe("clean output")
  })

  test("provider unavailability withholds output", async () => {
    const config = makeConfig({
      llm: {
        enabled: true,
        outputSanitizer: { enabled: true, tools: ["read"], actionMode: "redact" },
      },
    })
    const sanitizer = {
      shouldSanitize: () => true,
      isAvailable: () => false,
      sanitize: mock(async () => {
        throw new Error("should not be called")
      }),
    }
    const hook = createOutputRedactor(makeOutputDeps(config, { llmSanitizer: sanitizer }) as never)

    const output = { output: "clean output", title: "", metadata: {} }
    await hook({ tool: "read", sessionID: "s1", callID: "c1" }, output)

    expect(output.output.startsWith("[BLOCKED]")).toBe(true)
    expect(sanitizer.sanitize).not.toHaveBeenCalled()
  })

  test("provider disappearing after the availability gate still withholds output", async () => {
    const config = makeConfig({
      llm: {
        enabled: true,
        outputSanitizer: {
          enabled: true,
          tools: ["read"],
          actionMode: "redact",
          skipWhenRegexClean: false,
        },
      },
    })
    let availabilityChecks = 0
    const sanitizer = {
      shouldSanitize: () => true,
      // Available at the gate, then cooldown/unavailable immediately after.
      isAvailable: () => {
        availabilityChecks++
        return availabilityChecks === 1
      },
      sanitize: mock(async () => {
        throw new Error("All LLM providers failed: test: on cooldown")
      }),
    }
    const hook = createOutputRedactor(makeOutputDeps(config, { llmSanitizer: sanitizer }) as never)

    const output = { output: "clean output", title: "", metadata: {} }
    await hook({ tool: "read", sessionID: "s1", callID: "c1" }, output)

    expect(sanitizer.sanitize).toHaveBeenCalled()
    expect(output.output.startsWith("[BLOCKED]")).toBe(true)
  })
})
