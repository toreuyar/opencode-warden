import { describe, test, expect, mock } from "bun:test"
import { createPermissionHandler } from "../src/hooks/permission-handler.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import type { SecurityGuardConfig } from "../src/types.js"

function makeClient() {
  return {
    app: { log: mock(async () => {}) },
    session: { prompt: mock(async () => {}) },
    tui: { showToast: mock(async () => {}) },
  }
}

function makeAuditLogger() {
  return {
    log: mock(async () => {}),
    flush: () => {},
    destroy: () => {},
  }
}

function makeInput(overrides: Record<string, unknown> = {}) {
  return {
    id: "input-1",
    type: "bash",
    sessionID: "session-1",
    messageID: "msg-1",
    callID: "call-1",
    title: "ls -la",
    metadata: { command: "ls -la" },
    time: { created: Date.now() },
    ...overrides,
  }
}

function makeConfig(overrides: Record<string, unknown> = {}): SecurityGuardConfig {
  const base = { ...DEFAULT_CONFIG }
  if (overrides.llm) {
    base.llm = { ...base.llm, ...(overrides.llm as Record<string, unknown>) } as any
    if ((overrides.llm as any).safetyEvaluator) {
      base.llm.safetyEvaluator = {
        ...base.llm.safetyEvaluator,
        ...((overrides.llm as any).safetyEvaluator as Record<string, unknown>),
      } as any
    }
  }
  return base
}

describe("permission-handler", () => {
  describe("actionMode guard", () => {
    test("skips when actionMode is not 'permission'", async () => {
      const config = makeConfig({
        llm: { safetyEvaluator: { actionMode: "block" } },
      })
      const handler = createPermissionHandler({
        config,
        client: makeClient() as any,
        safetyEvaluator: null,
        evaluatedCalls: new Set(),
        auditLogger: makeAuditLogger() as any,
        diagnosticLogger: null,
      })
      const output = { status: "ask" as "ask" | "deny" | "allow" }
      await handler(makeInput() as any, output)
      // Status should remain unchanged (skipped)
      expect(output.status).toBe("ask")
    })

    test("skips when actionMode is 'warn'", async () => {
      const config = makeConfig({
        llm: { safetyEvaluator: { actionMode: "warn" } },
      })
      const handler = createPermissionHandler({
        config,
        client: makeClient() as any,
        safetyEvaluator: null,
        evaluatedCalls: new Set(),
        auditLogger: makeAuditLogger() as any,
        diagnosticLogger: null,
      })
      const output = { status: "ask" as "ask" | "deny" | "allow" }
      await handler(makeInput() as any, output)
      expect(output.status).toBe("ask")
    })
  })

  describe("permission mode with no safety evaluator", () => {
    test("denies when LLM is enabled but evaluator is null (fail-closed)", async () => {
      const config = makeConfig({
        llm: {
          enabled: true,
          safetyEvaluator: { actionMode: "permission", enabled: true },
        },
      })
      const auditLogger = makeAuditLogger()
      const handler = createPermissionHandler({
        config,
        client: makeClient() as any,
        safetyEvaluator: null,
        evaluatedCalls: new Set(),
        auditLogger: auditLogger as any,
        diagnosticLogger: null,
      })
      const output = { status: "ask" as "ask" | "deny" | "allow" }
      await handler(makeInput() as any, output)
      expect(output.status).toBe("deny")
      expect(auditLogger.log).toHaveBeenCalled()
    })

    test("skips when LLM is not enabled and evaluator is null", async () => {
      const config = makeConfig({
        llm: {
          enabled: false,
          safetyEvaluator: { actionMode: "permission", enabled: false },
        },
      })
      const handler = createPermissionHandler({
        config,
        client: makeClient() as any,
        safetyEvaluator: null,
        evaluatedCalls: new Set(),
        auditLogger: makeAuditLogger() as any,
        diagnosticLogger: null,
      })
      const output = { status: "ask" as "ask" | "deny" | "allow" }
      await handler(makeInput() as any, output)
      // Should skip, not deny
      expect(output.status).toBe("ask")
    })
  })

  describe("permission mode with safety evaluator", () => {
    test("skips tool not in evaluator's tool list", async () => {
      const config = makeConfig({
        llm: {
          enabled: true,
          safetyEvaluator: { actionMode: "permission", enabled: true },
        },
      })
      const evaluator = {
        shouldEvaluate: mock(() => false),
        isBypassed: mock(() => false),
        evaluate: mock(async () => ({})),
      }
      const auditLogger = makeAuditLogger()
      const handler = createPermissionHandler({
        config,
        client: makeClient() as any,
        safetyEvaluator: evaluator as any,
        evaluatedCalls: new Set(),
        auditLogger: auditLogger as any,
        diagnosticLogger: null,
      })
      const output = { status: "ask" as "ask" | "deny" | "allow" }
      await handler(makeInput({ type: "list" }) as any, output)
      expect(output.status).toBe("ask") // unchanged
      expect(evaluator.shouldEvaluate).toHaveBeenCalledWith("list")
    })

    test("auto-allows bypassed commands", async () => {
      const config = makeConfig({
        llm: {
          enabled: true,
          debug: false,
          safetyEvaluator: { actionMode: "permission", enabled: true },
        },
      })
      const evaluator = {
        shouldEvaluate: mock(() => true),
        isBypassed: mock(() => true),
        evaluate: mock(async () => ({})),
      }
      const evaluatedCalls = new Set<string>()
      const handler = createPermissionHandler({
        config,
        client: makeClient() as any,
        safetyEvaluator: evaluator as any,
        evaluatedCalls,
        auditLogger: makeAuditLogger() as any,
        diagnosticLogger: null,
      })
      const output = { status: "ask" as "ask" | "deny" | "allow" }
      await handler(makeInput() as any, output)
      expect(output.status).toBe("allow")
      expect(evaluatedCalls.has("call-1")).toBe(true)
    })

    test("denies when evaluation returns 'block'", async () => {
      const config = makeConfig({
        llm: {
          enabled: true,
          debug: false,
          safetyEvaluator: { actionMode: "permission", enabled: true },
        },
      })
      const evaluator = {
        shouldEvaluate: mock(() => true),
        isBypassed: mock(() => false),
        evaluate: mock(async () => ({
          safe: false,
          riskLevel: "critical",
          riskDimensions: ["destructive-operations"],
          explanation: "recursive delete on root",
          suggestedAlternative: "Use targeted deletion",
          recommendation: "block",
        })),
      }
      const client = makeClient()
      const handler = createPermissionHandler({
        config,
        client: client as any,
        safetyEvaluator: evaluator as any,
        evaluatedCalls: new Set(),
        auditLogger: makeAuditLogger() as any,
        diagnosticLogger: null,
      })
      const output = { status: "ask" as "ask" | "deny" | "allow" }
      await handler(makeInput({ metadata: { command: "rm -rf /" } }) as any, output)
      expect(output.status).toBe("deny")
    })

    test("sets 'ask' when evaluation returns 'warn'", async () => {
      const config = makeConfig({
        llm: {
          enabled: true,
          debug: false,
          safetyEvaluator: { actionMode: "permission", enabled: true },
        },
      })
      const evaluator = {
        shouldEvaluate: mock(() => true),
        isBypassed: mock(() => false),
        evaluate: mock(async () => ({
          safe: true,
          riskLevel: "medium",
          riskDimensions: ["service-disruption"],
          explanation: "service restart",
          suggestedAlternative: "",
          recommendation: "warn",
        })),
      }
      const handler = createPermissionHandler({
        config,
        client: makeClient() as any,
        safetyEvaluator: evaluator as any,
        evaluatedCalls: new Set(),
        auditLogger: makeAuditLogger() as any,
        diagnosticLogger: null,
      })
      const output = { status: "ask" as "ask" | "deny" | "allow" }
      await handler(makeInput() as any, output)
      expect(output.status).toBe("ask")
    })

    test("auto-allows when evaluation returns 'allow'", async () => {
      const config = makeConfig({
        llm: {
          enabled: true,
          debug: false,
          safetyEvaluator: { actionMode: "permission", enabled: true },
        },
      })
      const evaluator = {
        shouldEvaluate: mock(() => true),
        isBypassed: mock(() => false),
        evaluate: mock(async () => ({
          safe: true,
          riskLevel: "low",
          riskDimensions: [],
          explanation: "safe read-only operation",
          suggestedAlternative: "",
          recommendation: "allow",
        })),
      }
      const handler = createPermissionHandler({
        config,
        client: makeClient() as any,
        safetyEvaluator: evaluator as any,
        evaluatedCalls: new Set(),
        auditLogger: makeAuditLogger() as any,
        diagnosticLogger: null,
      })
      const output = { status: "ask" as "ask" | "deny" | "allow" }
      await handler(makeInput() as any, output)
      expect(output.status).toBe("allow")
    })

    test("extracts command from title when metadata.command is missing", async () => {
      const config = makeConfig({
        llm: {
          enabled: true,
          debug: false,
          safetyEvaluator: { actionMode: "permission", enabled: true },
        },
      })
      let capturedArgs: Record<string, unknown> = {}
      const evaluator = {
        shouldEvaluate: mock(() => true),
        isBypassed: mock((_tool: string, args: Record<string, unknown>) => {
          capturedArgs = args
          return true
        }),
        evaluate: mock(async () => ({})),
      }
      const handler = createPermissionHandler({
        config,
        client: makeClient() as any,
        safetyEvaluator: evaluator as any,
        evaluatedCalls: new Set(),
        auditLogger: makeAuditLogger() as any,
        diagnosticLogger: null,
      })
      const output = { status: "ask" as "ask" | "deny" | "allow" }
      await handler(makeInput({
        type: "bash",
        title: "git status",
        metadata: {},
      }) as any, output)
      expect(capturedArgs.command).toBe("git status")
    })
  })
})
