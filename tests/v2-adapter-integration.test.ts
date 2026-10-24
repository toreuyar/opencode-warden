import { afterEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"
import warden from "../src/index.js"
import { createDetectionEngine } from "../src/detection/index.js"
import { AuditLogger } from "../src/audit/index.js"
import { SessionStats } from "../src/audit/session-stats.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import { createInputSanitizer } from "../src/hooks/input-sanitizer.js"
import { createOutputRedactor } from "../src/hooks/output-redactor.js"
import { createPermissionHandler } from "../src/hooks/permission-handler.js"
import {
  createExecuteAfterAdapter,
  createPermissionAdapter,
  FAIL_CLOSED_MESSAGES,
  redactMetadataValues,
  type ToolAfterEvent,
} from "../src/hooks/v2-adapters.js"
import { LlmSanitizer } from "../src/llm/index.js"
import { ProviderChain } from "../src/llm/provider-chain.js"
import type {
  PluginClient,
  SecurityGuardConfig,
  ToastState,
  WrittenFileMetadata,
} from "../src/types.js"

const SECRET = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

const mockClient: PluginClient = {
  app: { log: async () => undefined },
  tui: { showToast: async () => undefined },
  session: { prompt: async () => undefined },
}

const testAuditConfig = { ...DEFAULT_CONFIG.audit, enabled: false }

const tempDirs: string[] = []
const originalHome = process.env.HOME

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  }
  if (originalHome === undefined) delete process.env.HOME
  else process.env.HOME = originalHome
})

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "warden-v2-adapter-"))
  tempDirs.push(dir)
  return dir
}

function createDeps() {
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

function makeOutputRedactor(
  config: SecurityGuardConfig,
  deps = createDeps(),
  llmSanitizer: LlmSanitizer | null = null,
) {
  return createOutputRedactor({
    ...deps,
    config,
    client: mockClient,
    llmSanitizer,
  })
}

function makeAfterAdapter(
  config: SecurityGuardConfig,
  llmSanitizer: LlmSanitizer | null = null,
) {
  const deps = createDeps()
  return {
    deps,
    adapter: createExecuteAfterAdapter({
      redactor: makeOutputRedactor(config, deps, llmSanitizer),
      engine: deps.engine,
    }),
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Output after-hook adapter
// ─────────────────────────────────────────────────────────────────────────────

describe("V2 execute.after adapter", () => {
  test("redacts textual content and metadata", async () => {
    const { adapter } = makeAfterAdapter(DEFAULT_CONFIG)
    const event: ToolAfterEvent = {
      tool: "read",
      sessionID: "s1",
      id: "call-1",
      input: { path: "/project/src/app.ts" },
      status: "completed",
      result: {
        content: `const key = "${SECRET}"`,
        metadata: { title: `t ${SECRET}`, nested: { token: SECRET } },
      },
    }

    await adapter(event)

    if (event.status !== "completed") throw new Error("unreachable")
    expect(event.result.content).toContain("[REDACTED]")
    expect(JSON.stringify(event.result)).not.toContain(SECRET)
  })

  test("sanitizes content-less structured output via JSON fallback", async () => {
    const { adapter } = makeAfterAdapter(DEFAULT_CONFIG)
    const event: ToolAfterEvent = {
      tool: "read",
      sessionID: "s1",
      id: "call-2",
      input: { path: "/project/src/app.ts" },
      status: "completed",
      result: {
        output: { token: SECRET, keep: 1 },
      },
    }

    await adapter(event)

    if (event.status !== "completed") throw new Error("unreachable")
    expect(typeof event.result.content).toBe("string")
    expect(event.result.content as string).toContain("[REDACTED]")
    expect(event.result.content as string).not.toContain(SECRET)
    // The raw structured copy must not remain after redaction.
    expect(event.result.output).toBeUndefined()
    expect(JSON.stringify(event.result)).not.toContain(SECRET)
  })

  test("keeps content-less structured output when clean", async () => {
    const { adapter } = makeAfterAdapter(DEFAULT_CONFIG)
    const event: ToolAfterEvent = {
      tool: "read",
      sessionID: "s1",
      id: "call-3",
      input: { path: "/project/src/app.ts" },
      status: "completed",
      result: { output: { count: 2, ok: true } },
    }

    await adapter(event)

    if (event.status !== "completed") throw new Error("unreachable")
    expect(event.result.content).toBeUndefined()
    expect(event.result.output).toEqual({ count: 2, ok: true })
    expect(event.result.metadata).toBeUndefined()
  })

  test("sanitizes the model-visible error cause and drops it", async () => {
    const { adapter } = makeAfterAdapter(DEFAULT_CONFIG)
    const event: ToolAfterEvent = {
      tool: "read",
      sessionID: "s1",
      id: "call-4",
      input: { path: "/project/src/app.ts" },
      status: "error",
      error: {
        // OpenCode's toSessionError prefers the inner cause message.
        message: "Unable to read file",
        error: new Error(`provider failed with ${SECRET}`),
        metadata: { title: "read failed", nested: { token: SECRET } },
      },
    }

    await adapter(event)

    if (event.status !== "error") throw new Error("unreachable")
    expect(event.error.message).toContain("[REDACTED]")
    expect(event.error.message).not.toContain(SECRET)
    // The unsanitized cause must never become model-visible later.
    expect(event.error.error).toBeUndefined()
    expect(JSON.stringify(event.error.metadata)).not.toContain(SECRET)
  })

  test("withholds output and error metadata when the enabled LLM is unavailable", async () => {
    const config: SecurityGuardConfig = {
      ...DEFAULT_CONFIG,
      llm: {
        ...DEFAULT_CONFIG.llm,
        enabled: true,
        outputSanitizer: {
          ...DEFAULT_CONFIG.llm.outputSanitizer,
          enabled: true,
          skipWhenRegexClean: false,
          providers: [],
        },
      },
    }
    const sanitizer = new LlmSanitizer(config.llm, new ProviderChain([]))
    const { adapter } = makeAfterAdapter(config, sanitizer)

    const completed: ToolAfterEvent = {
      tool: "read",
      sessionID: "s1",
      id: "call-5",
      input: { path: "/project/src/app.ts" },
      status: "completed",
      result: { output: { token: SECRET } },
    }
    await adapter(completed)

    if (completed.status !== "completed") throw new Error("unreachable")
    expect(completed.result.content as string).toContain("[BLOCKED]")
    expect(completed.result.output).toBeUndefined()
    expect(completed.result.metadata).toEqual({ title: "[BLOCKED] Output withheld" })
    expect(JSON.stringify(completed.result)).not.toContain(SECRET)

    const failed: ToolAfterEvent = {
      tool: "read",
      sessionID: "s1",
      id: "call-6",
      input: { path: "/project/src/app.ts" },
      status: "error",
      error: {
        message: `read failed with ${SECRET}`,
        metadata: { token: SECRET },
      },
    }
    await adapter(failed)

    if (failed.status !== "error") throw new Error("unreachable")
    expect(failed.error.message).toContain("[BLOCKED]")
    expect(failed.error.message).not.toContain(SECRET)
    expect(failed.error.metadata).toBeUndefined()
    expect(failed.error.error).toBeUndefined()
    expect(JSON.stringify(failed.error)).not.toContain(SECRET)
  })

  test("fails closed if the redactor throws", async () => {
    const adapter = createExecuteAfterAdapter({
      engine: createDetectionEngine(DEFAULT_CONFIG),
      redactor: async () => {
        throw new Error("boom")
      },
    })
    const event: ToolAfterEvent = {
      tool: "read",
      sessionID: "s1",
      id: "call-7",
      input: {},
      status: "error",
      error: { message: `raw ${SECRET}`, error: new Error("cause") },
    }

    await adapter(event)

    if (event.status !== "error") throw new Error("unreachable")
    expect(event.error.message).toContain("[BLOCKED]")
    expect(event.error.message).not.toContain(SECRET)
    expect(event.error.error).toBeUndefined()
    expect(event.error.metadata).toBeUndefined()
  })

  test("preserves file content parts while redacting sibling text parts", async () => {
    const { adapter } = makeAfterAdapter(DEFAULT_CONFIG)
    const filePart = {
      type: "file" as const,
      uri: "file:///project/report.pdf",
      mime: "application/pdf",
      name: "report.pdf",
    }
    const event: ToolAfterEvent = {
      tool: "read",
      sessionID: "s1",
      id: "call-parts",
      input: { path: "/project/src/app.ts" },
      status: "completed",
      result: {
        content: [
          { type: "text", text: `key ${SECRET}` },
          filePart,
          { type: "text", text: "clean text" },
        ],
        metadata: { title: "result" },
      },
    }

    await adapter(event)

    if (event.status !== "completed") throw new Error("unreachable")
    expect(Array.isArray(event.result.content)).toBe(true)
    const parts = event.result.content as Array<Record<string, unknown>>
    expect(parts).toHaveLength(3)
    expect(parts[0].type).toBe("text")
    expect(parts[0].text).toContain("[REDACTED]")
    expect(parts[0].text).not.toContain(SECRET)
    expect(parts[1]).toEqual(filePart)
    expect(parts[2]).toEqual({ type: "text", text: "clean text" })
    expect(JSON.stringify(event.result)).not.toContain(SECRET)
  })

  test("sanitizes metadata even when content has no text parts", async () => {
    const { adapter } = makeAfterAdapter(DEFAULT_CONFIG)
    const filePart = {
      type: "file" as const,
      uri: "file:///project/archive.zip",
      mime: "application/zip",
    }
    const event: ToolAfterEvent = {
      tool: "read",
      sessionID: "s1",
      id: "call-file-only",
      input: { path: "/project/archive.zip" },
      status: "completed",
      result: {
        content: [filePart],
        metadata: { title: `archive ${SECRET}`, nested: { token: SECRET } },
      },
    }

    await adapter(event)

    if (event.status !== "completed") throw new Error("unreachable")
    expect(event.result.content).toEqual([filePart])
    expect(JSON.stringify(event.result.metadata)).not.toContain(SECRET)
    expect(JSON.stringify(event.result)).not.toContain(SECRET)
  })

  test("metadata redaction is structural, bounded, and non-mutating", () => {
    const engine = createDetectionEngine(DEFAULT_CONFIG)
    const source = {
      nested: { token: SECRET },
      list: [SECRET],
      [SECRET]: "secret-keyed",
      count: 1,
    }
    const result = redactMetadataValues(source, engine) as Record<string, unknown>

    expect(JSON.stringify(result)).not.toContain(SECRET)
    expect(Object.keys(result).join(",")).not.toContain(SECRET)
    expect((source.nested as { token: string }).token).toBe(SECRET)
    expect(result.count).toBe(1)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Permission adapter
// ─────────────────────────────────────────────────────────────────────────────

describe("V2 permission adapter", () => {
  test("forwards action, resources, source call id, and denial message", async () => {
    let captured: any
    const adapter = createPermissionAdapter(async (input, output) => {
      captured = input
      output.status = "deny"
      output.message = "denied by test"
    })
    const event = {
      sessionID: "s1",
      action: "read",
      resources: ["/project/.env"],
      metadata: { command: "cat .env" },
      source: { type: "tool", messageID: "msg-1", id: "call-42" },
      effect: "ask" as const,
    }

    await adapter(event)

    expect(captured.action).toBe("read")
    expect(captured.resources).toEqual(["/project/.env"])
    expect(captured.callID).toBe("call-42")
    expect(captured.id).toBe("call-42")
    expect(captured.messageID).toBe("msg-1")
    expect(captured.title).toBe("cat .env")
    expect(event.effect).toBe("deny")
    expect(event.message).toBe("denied by test")
    // The input's original V2 explanation is preserved when not overwritten.
    expect(captured.message).toBeUndefined()
  })

  test("source.id is the shared dedup key with execute.before", async () => {
    const config: SecurityGuardConfig = {
      ...DEFAULT_CONFIG,
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
    const deps = createDeps()
    const calls = { evaluate: 0 }
    const evaluator = {
      shouldEvaluate: () => true,
      isBypassed: () => false,
      async evaluate() {
        calls.evaluate++
        return {
          safe: true,
          riskLevel: "none" as const,
          riskDimensions: [],
          explanation: "safe",
          suggestedAlternative: "",
          recommendation: "allow" as const,
        }
      },
    }

    const permissionHandler = createPermissionHandler({
      config,
      client: mockClient,
      auditLogger: deps.auditLogger,
      diagnosticLogger: null,
      getSessionState: () => ({
        safetyEvaluator: evaluator as any,
        evaluatedCalls: deps.evaluatedCalls,
        sessionAllowlist: deps.sessionAllowlist,
      }),
    })
    const adapter = createPermissionAdapter(permissionHandler)
    const permissionEvent = {
      sessionID: "s1",
      action: "read",
      resources: ["/project/src/app.ts"],
      source: { type: "tool", messageID: "msg-1", id: "call-42" },
      effect: "ask" as const,
    }

    await adapter(permissionEvent)

    expect(permissionEvent.effect).toBe("allow")
    expect(deps.evaluatedCalls.has("call-42")).toBe(true)
    expect(calls.evaluate).toBe(1)

    const inputSanitizer = createInputSanitizer({
      ...deps,
      config,
      client: mockClient,
      safetyEvaluator: evaluator as any,
    })
    await inputSanitizer(
      { tool: "read", sessionID: "s1", callID: "call-42" },
      { args: { path: "/project/src/app.ts" } },
    )

    // execute.before with the same Tool.CallID must not evaluate a second time.
    expect(calls.evaluate).toBe(1)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// setup() integration: inline config + fail-closed config source
// ─────────────────────────────────────────────────────────────────────────────

interface FakeHookCall {
  readonly domain: string
  readonly name: string
  readonly callback: (event: any) => any
}

function makeFakeCtx(options: unknown, directory: string) {
  const hooks = new Map<string, FakeHookCall>()
  const calls = {
    transforms: 0,
    synthetic: 0,
    subscribe: 0,
  }

  const domain = (name: string) => ({
    hook: async (hookName: string, callback: (event: any) => any) => {
      hooks.set(`${name}.${hookName}`, { domain: name, name: hookName, callback })
      return { dispose: async () => undefined }
    },
  })

  const ctx = {
    location: { directory },
    options,
    permission: domain("permission"),
    shell: domain("shell"),
    session: {
      ...domain("session"),
      synthetic: async () => {
        calls.synthetic++
      },
    },
    tool: {
      ...domain("tool"),
      transform: async () => {
        calls.transforms++
        return { dispose: async () => undefined }
      },
      list: async () => [],
      reload: async () => undefined,
    },
    event: {
      subscribe: () => {
        calls.subscribe++
        return (async function* () {})()
      },
    },
  }

  return { ctx, hooks, calls }
}

const VALID_INLINE_CONFIG = {
  notifications: false,
  audit: { enabled: false },
  diagnosticLog: { enabled: false },
  blockedTools: ["subagent"],
  llm: {
    enabled: true,
    safetyEvaluator: {
      enabled: true,
      actionMode: "permission",
      providers: [],
      // blockedTools is checked after the evaluator's tool filter, so the test
      // includes subagent in the evaluated surface.
      tools: ["shell", "write", "edit", "patch", "read", "webfetch", "subagent"],
    },
    outputSanitizer: {
      enabled: true,
      providers: [],
      skipWhenRegexClean: false,
    },
  },
}

describe("setup() integration", () => {
  test("valid inline config is wired into the permission adapter", async () => {
    const directory = makeTempDir()
    process.env.HOME = makeTempDir() // no global config
    const { ctx, hooks, calls } = makeFakeCtx(VALID_INLINE_CONFIG, directory)

    const originalLog = console.log
    const originalError = console.error
    console.log = () => undefined
    console.error = () => undefined
    const cleanup = await warden.setup(ctx as any)
    try {
      // Inline options were accepted and the normal hook path was installed.
      expect(calls.transforms).toBe(1)
      expect(hooks.has("permission.evaluate")).toBe(true)
      expect(hooks.has("tool.execute.before")).toBe(true)
      expect(hooks.has("tool.execute.after")).toBe(true)

      const permission = hooks.get("permission.evaluate")!.callback

      // Path permission: deterministic deny from V2 resources.
      const pathEvent = {
        sessionID: "s1",
        action: "read",
        resources: [join(directory, ".env")],
        source: { type: "tool", messageID: "msg-1", id: "call-path" },
        effect: "ask",
      }
      await permission(pathEvent)
      expect(pathEvent.effect).toBe("deny")
      expect(pathEvent.message).toContain("blocked by security policy")

      // Subagent permission: inline blockedTools applies to V2 action.
      const subagentEvent = {
        sessionID: "s1",
        action: "subagent",
        resources: ["reviewer"],
        source: { type: "tool", messageID: "msg-2", id: "call-subagent" },
        effect: "ask",
      }
      await permission(subagentEvent)
      expect(subagentEvent.effect).toBe("deny")
      expect(subagentEvent.message).toContain("blocked by security policy")

      // Shell permission: empty provider chain must fail closed at evaluation.
      const shellEvent = {
        sessionID: "s1",
        action: "shell",
        resources: ["rm -rf /tmp/warden-test"],
        source: { type: "tool", messageID: "msg-3", id: "call-shell" },
        effect: "ask",
      }
      await permission(shellEvent)
      expect(shellEvent.effect).toBe("deny")
      expect(shellEvent.message).toContain("denied")

      // Content-less structured output is withheld when the enabled LLM is down.
      const after = hooks.get("tool.execute.after")!.callback
      const completed = {
        tool: "read",
        sessionID: "s1",
        id: "call-after",
        input: { path: join(directory, "src/app.ts") },
        status: "completed",
        result: { output: { token: SECRET } },
      }
      await after(completed)
      expect(completed.result.content).toContain("[BLOCKED]")
      expect(completed.result.output).toBeUndefined()
      expect(JSON.stringify(completed.result)).not.toContain(SECRET)
    } finally {
      console.log = originalLog
      console.error = originalError
      if (cleanup) await cleanup()
    }
  })

  test("invalid inline options fail closed without initializing providers", async () => {
    const directory = makeTempDir()
    process.env.HOME = makeTempDir()
    const { ctx, hooks, calls } = makeFakeCtx(
      { llm: { enabled: "yes", apiKey: SECRET } },
      directory,
    )

    const errors: string[] = []
    const originalError = console.error
    const originalFetch = globalThis.fetch
    let fetchCalls = 0
    console.error = (...args: unknown[]) => {
      errors.push(args.map(String).join(" "))
    }
    globalThis.fetch = (async () => {
      fetchCalls++
      throw new Error("network disabled in test")
    }) as any

    let cleanup: any
    try {
      cleanup = await warden.setup(ctx as any)
    } finally {
      console.error = originalError
      globalThis.fetch = originalFetch
    }

    try {
      expect(typeof cleanup).toBe("function")
      expect(errors.join("\n")).toContain("(inline)")
      expect(errors.join("\n")).not.toContain(SECRET)
      expect(calls.transforms).toBe(0)
      expect(calls.synthetic).toBe(0)
      expect(calls.subscribe).toBe(0)
      expect(fetchCalls).toBe(0)
      expect(hooks.has("permission.evaluate")).toBe(true)
      expect(hooks.has("session.context")).toBe(true)
      expect(hooks.has("shell.create.before")).toBe(true)

      const permission = {
        sessionID: "s1",
        action: "shell",
        resources: ["ls"],
        effect: "allow",
      }
      await hooks.get("permission.evaluate")!.callback(permission)
      expect(permission.effect).toBe("deny")
    } finally {
      if (cleanup) await cleanup()
    }
  })

  test("invalid file source registers deny-all hooks, never throws, and keeps diagnostics sanitized", async () => {
    const directory = makeTempDir()
    const home = makeTempDir()
    process.env.HOME = home
    mkdirSync(join(directory, ".opencode"), { recursive: true })
    writeFileSync(
      join(directory, ".opencode", "opencode-warden.json"),
      JSON.stringify({
        llm: { enabled: "yes", apiKey: SECRET },
      }),
    )

    const { ctx, hooks, calls } = makeFakeCtx({}, directory)
    const errors: string[] = []
    const originalError = console.error
    const originalFetch = globalThis.fetch
    let fetchCalls = 0
    console.error = (...args: unknown[]) => {
      errors.push(args.map(String).join(" "))
    }
    globalThis.fetch = (async () => {
      fetchCalls++
      throw new Error("network disabled in test")
    }) as any

    let cleanup: any
    try {
      cleanup = await warden.setup(ctx as any)
    } finally {
      console.error = originalError
      globalThis.fetch = originalFetch
    }

    try {
      // setup must return normally; OpenCode drops plugins that throw.
      expect(typeof cleanup).toBe("function")
      expect(errors.join("\n")).toContain("configuration")
      expect(errors.join("\n")).not.toContain(SECRET)

      // No normal components/tools/providers are constructed on this path.
      expect(calls.transforms).toBe(0)
      expect(calls.synthetic).toBe(0)
      expect(calls.subscribe).toBe(0)
      // No ProviderChain health check or other outbound LLM capability.
      expect(fetchCalls).toBe(0)

      expect(hooks.has("permission.evaluate")).toBe(true)
      expect(hooks.has("tool.execute.before")).toBe(true)
      expect(hooks.has("tool.execute.after")).toBe(true)
      expect(hooks.has("session.prompt")).toBe(true)
      expect(hooks.has("session.context")).toBe(true)
      expect(hooks.has("session.compaction")).toBe(true)
      expect(hooks.has("session.generate")).toBe(true)
      expect(hooks.has("session.title")).toBe(true)
      expect(hooks.has("session.model.request")).toBe(true)
      expect(hooks.has("session.http.request")).toBe(true)
      expect(hooks.has("session.experimental.ws.handshake")).toBe(true)
      expect(hooks.has("session.experimental.ws.send")).toBe(true)
      expect(hooks.has("shell.create.before")).toBe(true)

      const permission = {
        sessionID: "s1",
        action: "read",
        resources: ["/project/.env"],
        effect: "ask",
      }
      await hooks.get("permission.evaluate")!.callback(permission)
      expect(permission.effect).toBe("deny")
      expect((permission as any).message).toBe(FAIL_CLOSED_MESSAGES.permission)

      for (const key of [
        "tool.execute.before",
        "session.prompt",
        "session.context",
        "session.compaction",
        "session.generate",
        "session.title",
        "session.model.request",
        "session.http.request",
        "session.experimental.ws.handshake",
        "session.experimental.ws.send",
        "shell.create.before",
      ]) {
        expect(() => hooks.get(key)!.callback({})).toThrow(/Security Guard: Warden configuration is invalid/)
      }

      const failed = {
        tool: "read",
        sessionID: "s1",
        id: "call-error",
        input: { path: "/project/.env" },
        status: "error",
        error: {
          message: `raw ${SECRET}`,
          error: new Error(`cause ${SECRET}`),
          metadata: { token: SECRET },
        },
      }
      await hooks.get("tool.execute.after")!.callback(failed)
      expect(failed.error.message).toBe(FAIL_CLOSED_MESSAGES.error)
      expect(failed.error.error).toBeUndefined()
      expect(failed.error.metadata).toBeUndefined()
      expect(JSON.stringify(failed)).not.toContain(SECRET)

      const completed = {
        tool: "read",
        sessionID: "s1",
        id: "call-completed",
        input: { path: "/project/.env" },
        status: "completed",
        result: { content: `raw ${SECRET}`, output: { token: SECRET }, metadata: { token: SECRET } },
      }
      await hooks.get("tool.execute.after")!.callback(completed)
      expect(completed.result).toEqual({
        content: FAIL_CLOSED_MESSAGES.output,
        output: undefined,
        metadata: undefined,
      })
      expect(JSON.stringify(completed)).not.toContain(SECRET)
    } finally {
      if (cleanup) await cleanup()
    }
  })
})
