import { afterEach, describe, expect, test } from "bun:test"
import { existsSync, mkdtempSync, rmSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"
import warden, {
  MIN_SUPPORTED_OPENCODE_VERSION,
  TYPED_TOOL_VETO_OPENCODE_VERSION,
  isRuntimeVersionSupported,
  isTypedToolVetoSupported,
  runtimeCompatibilityWarning,
} from "../src/index.js"
import { AuditLogger } from "../src/audit/index.js"
import { SessionStats } from "../src/audit/session-stats.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import { createDetectionEngine } from "../src/detection/index.js"
import { createCompactionContext } from "../src/hooks/compaction-context.js"
import { createOutboundSanitizer } from "../src/hooks/outbound-sanitizer.js"
import { createPromptSanitizer } from "../src/hooks/prompt-sanitizer.js"
import {
  buildSessionDenyRules,
  createSessionPermissionSync,
  mergePermissionRules,
} from "../src/hooks/session-permissions.js"
import type {
  PermissionRule,
  PluginClient,
  SecurityGuardConfig,
} from "../src/types.js"

const SECRET = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
const POLICY = "## Warden Security Policy\n\nstable test policy"

const tempDirs: string[] = []
const originalHome = process.env.HOME
const originalLog = console.log
const originalWarn = console.warn
const originalError = console.error

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  }
  if (originalHome === undefined) delete process.env.HOME
  else process.env.HOME = originalHome
  console.log = originalLog
  console.warn = originalWarn
  console.error = originalError
})

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "warden-v2-session-policy-"))
  tempDirs.push(dir)
  return dir
}

function config(overrides: Partial<SecurityGuardConfig> = {}): SecurityGuardConfig {
  return { ...DEFAULT_CONFIG, ...overrides }
}

const mockClient: PluginClient = {
  app: { log: async () => undefined },
  tui: { showToast: async () => undefined },
  session: { prompt: async () => undefined },
}

// ─────────────────────────────────────────────────────────────────────────────
// Session permission rule translation
// ─────────────────────────────────────────────────────────────────────────────

describe("session permission deny-rule translation", () => {
  test("blockedTools translate to canonical + alias deny rules", () => {
    const rules = buildSessionDenyRules(
      config({ blockedTools: ["shell", "task", "my-tool"] }),
    )

    expect(rules).toEqual(
      expect.arrayContaining([
        { action: "shell", resource: "*", effect: "deny" },
        { action: "bash", resource: "*", effect: "deny" },
        { action: "subagent", resource: "*", effect: "deny" },
        { action: "task", resource: "*", effect: "deny" },
        { action: "my-tool", resource: "*", effect: "deny" },
      ]),
    )
  })

  test("blockedTools wildcard entries are omitted instead of broadening the deny", () => {
    expect(buildSessionDenyRules(config({ blockedTools: ["sh*", "task?"] }))).toEqual([])
  })

  test("literal absolute blocked paths deny read and write actions", () => {
    const path = "/srv/secrets/production.pem"
    const rules = buildSessionDenyRules(
      config({
        blockedFilePaths: [path],
        writeProtectedPaths: [],
        whitelistedPaths: [],
      }),
    )

    for (const action of ["read", "glob", "grep", "write", "edit", "patch"]) {
      expect(rules).toContainEqual({ action, resource: path, effect: "deny" })
    }
  })

  test("in-project absolute paths also emit the host's relative resource", () => {
    const rules = buildSessionDenyRules(
      config({
        blockedFilePaths: ["/project/config/.env"],
        writeProtectedPaths: [],
        whitelistedPaths: [],
      }),
      "/project",
    )

    for (const action of ["read", "glob", "grep", "write", "edit", "patch"]) {
      expect(rules).toContainEqual({
        action,
        resource: "/project/config/.env",
        effect: "deny",
      })
      expect(rules).toContainEqual({
        action,
        resource: "config/.env",
        effect: "deny",
      })
    }
  })

  test("outside-project absolute paths do not invent a relative resource", () => {
    const rules = buildSessionDenyRules(
      config({
        blockedFilePaths: ["/srv/secrets/production.pem"],
        writeProtectedPaths: [],
        whitelistedPaths: [],
      }),
      "/project",
    )

    expect(rules.some((rule) => rule.resource === "../srv/secrets/production.pem")).toBe(false)
    expect(rules).toContainEqual({
      action: "read",
      resource: "/srv/secrets/production.pem",
      effect: "deny",
    })
  })

  test("writeProtectedPaths deny only write actions (reads stay allowed)", () => {
    const path = "/var/log/warden.log"
    const rules = buildSessionDenyRules(
      config({
        blockedFilePaths: [],
        writeProtectedPaths: [path],
        whitelistedPaths: [],
      }),
    )

    expect(rules).toEqual(
      expect.arrayContaining([
        { action: "write", resource: path, effect: "deny" },
        { action: "edit", resource: path, effect: "deny" },
        { action: "patch", resource: path, effect: "deny" },
      ]),
    )
    expect(rules.some((rule) => rule.action === "read")).toBe(false)
    expect(rules.some((rule) => rule.action === "glob")).toBe(false)
    expect(rules.some((rule) => rule.action === "grep")).toBe(false)
  })

  test("glob and relative path entries are omitted (not exactly representable)", () => {
    const rules = buildSessionDenyRules(
      config({
        blockedFilePaths: ["/srv/**/*.pem", "**/.env", "local.secret", "~/id_rsa"],
        writeProtectedPaths: [],
      }),
    )
    expect(rules).toEqual([])
  })

  test("an exact whitelist entry suppresses the translated deny rule", () => {
    const path = "/srv/shared/public.pem"
    const rules = buildSessionDenyRules(
      config({
        blockedFilePaths: [path],
        writeProtectedPaths: [],
        whitelistedPaths: [path],
      }),
    )
    expect(rules).toEqual([])
  })

  test("merge preserves existing host rules in order and appends only missing denies", () => {
    const existing: PermissionRule[] = [
      { action: "read", resource: "docs/*", effect: "allow" },
      { action: "shell", resource: "*", effect: "deny" },
    ]
    const wardenRules: PermissionRule[] = [
      { action: "shell", resource: "*", effect: "deny" },
      { action: "read", resource: "/srv/secret.pem", effect: "deny" },
    ]

    expect(mergePermissionRules(existing, wardenRules)).toEqual([
      { action: "read", resource: "docs/*", effect: "allow" },
      { action: "shell", resource: "*", effect: "deny" },
      { action: "read", resource: "/srv/secret.pem", effect: "deny" },
    ])
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Session permission sync coordinator
// ─────────────────────────────────────────────────────────────────────────────

function createPermissionSyncHarness() {
  const state = {
    current: [
      { action: "read", resource: "docs/*", effect: "allow" },
    ] as PermissionRule[],
    updates: [] as PermissionRule[][],
    gets: 0,
    failGet: false,
    failUpdate: false,
  }

  const sync = createSessionPermissionSync({
    config: config({ blockedTools: ["shell"] }),
    diagnosticLogger: null,
    getSessionPermissions: async () => {
      state.gets++
      if (state.failGet) throw new Error("get failed")
      return state.current.map((rule) => ({ ...rule }))
    },
    updateSessionPermissions: async (_sessionID, permissions) => {
      if (state.failUpdate) throw new Error("update failed")
      state.updates.push(permissions.map((rule) => ({ ...rule })))
      state.current = permissions.map((rule) => ({ ...rule }))
    },
  })

  return { sync, state }
}

describe("session permission sync", () => {
  test("reads current rules, preserves them, and appends Warden denies", async () => {
    const { sync, state } = createPermissionSyncHarness()

    await expect(sync.sync("s1")).resolves.toBe(true)

    expect(state.gets).toBe(2)
    expect(state.updates).toHaveLength(1)
    expect(state.updates[0][0]).toEqual({
      action: "read",
      resource: "docs/*",
      effect: "allow",
    })
    expect(state.updates[0]).toContainEqual({
      action: "shell",
      resource: "*",
      effect: "deny",
    })
    expect(state.updates[0]).toContainEqual({
      action: "bash",
      resource: "*",
      effect: "deny",
    })
  })

  test("later calls reuse the settled sync without another host read/update", async () => {
    const { sync, state } = createPermissionSyncHarness()
    await sync.sync("s1")
    await sync.sync("s1")
    expect(state.gets).toBe(2)
    expect(state.updates).toHaveLength(1)
  })

  test("concurrent lazy calls share one in-flight sync", async () => {
    const { sync, state } = createPermissionSyncHarness()

    const [a, b] = await Promise.all([sync.sync("s1"), sync.sync("s1")])

    expect(a).toBe(true)
    expect(b).toBe(true)
    expect(state.gets).toBe(2)
    expect(state.updates).toHaveLength(1)
  })

  test("defers an update when the host ruleset changed between read and write", async () => {
    let gets = 0
    let updates = 0
    const sync = createSessionPermissionSync({
      config: config({ blockedTools: ["shell"] }),
      diagnosticLogger: null,
      getSessionPermissions: async () => {
        gets++
        return gets === 1
          ? [{ action: "read", resource: "docs/*", effect: "allow" }]
          : [{ action: "read", resource: "secrets/*", effect: "deny" }]
      },
      updateSessionPermissions: async () => {
        updates++
      },
    })

    await expect(sync.sync("s1")).resolves.toBe(false)
    expect(gets).toBe(2)
    expect(updates).toBe(0)
  })

  test("read failure is non-throwing and retries on a later call", async () => {
    const { sync, state } = createPermissionSyncHarness()
    state.failGet = true

    await expect(sync.sync("s1")).resolves.toBe(false)
    expect(state.updates).toHaveLength(0)

    state.failGet = false
    await expect(sync.sync("s1")).resolves.toBe(true)
    expect(state.gets).toBe(3)
    expect(state.updates).toHaveLength(1)
  })

  test("update failure is non-throwing and retries on a later call", async () => {
    const { sync, state } = createPermissionSyncHarness()
    state.failUpdate = true

    await expect(sync.sync("s1")).resolves.toBe(false)
    state.failUpdate = false

    await expect(sync.sync("s1")).resolves.toBe(true)
    expect(state.updates).toHaveLength(1)
  })

  test("forget drops state race-safely, including while a sync is in flight", async () => {
    let releaseFirst: (() => void) | null = null
    const gate = new Promise<void>((resolve) => {
      releaseFirst = resolve
    })
    let gets = 0
    const updates: PermissionRule[][] = []

    const sync = createSessionPermissionSync({
      config: config({ blockedTools: ["shell"] }),
      diagnosticLogger: null,
      getSessionPermissions: async () => {
        gets++
        if (gets === 1) await gate
        return []
      },
      updateSessionPermissions: async (_id, permissions) => {
        updates.push(permissions.map((rule) => ({ ...rule })))
      },
    })

    const first = sync.sync("s1")
    sync.forget("s1")
    const second = sync.sync("s1")
    releaseFirst!()

    await expect(first).resolves.toBe(true)
    await expect(second).resolves.toBe(true)

    // A settled third call uses the post-forget sync, not stale state.
    await sync.sync("s1")
    expect(gets).toBe(4)
    expect(updates).toHaveLength(2)
  })

  test("empty translation performs no host read or update", async () => {
    let gets = 0
    let updates = 0
    const sync = createSessionPermissionSync({
      config: config({ blockedTools: [], blockedFilePaths: [], writeProtectedPaths: [] }),
      diagnosticLogger: null,
      getSessionPermissions: async () => {
        gets++
        return []
      },
      updateSessionPermissions: async () => {
        updates++
      },
    })

    await expect(sync.sync("s1")).resolves.toBe(true)
    expect(gets).toBe(0)
    expect(updates).toBe(0)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Prompt attachment metadata scanning
// ─────────────────────────────────────────────────────────────────────────────

function createPromptHook(cfg: SecurityGuardConfig) {
  const engine = createDetectionEngine(cfg)
  const sessionStats = new SessionStats("test")
  const toastState = { lastToastTime: 0, minInterval: 0 }

  const hook = createPromptSanitizer({
    engine,
    config: cfg,
    auditLogger: new AuditLogger({ ...DEFAULT_CONFIG.audit, enabled: false }),
    client: mockClient,
    diagnosticLogger: null,
    getSessionState: () => ({ sessionStats, toastState }),
  })

  return { hook, sessionStats }
}

describe("prompt attachment metadata scanning", () => {
  const enabled = config({ scanUserPrompts: true })

  test("clean attachment metadata passes through", async () => {
    const { hook } = createPromptHook(enabled)
    const output = {
      message: {},
      parts: [{ type: "text", text: "review this diagram" }],
      attachments: {
        files: [
          { uri: "file:///project/diagram.png", name: "diagram.png", description: "architecture" },
        ],
        agents: [{ name: "build" }],
        skills: [{ id: "diagramming", name: "Diagramming" }],
      },
    }

    await expect(hook({ sessionID: "s1", messageID: "m1" }, output)).resolves.toBeUndefined()
  })

  test.each([
    ["file name", { files: [{ uri: "file:///project/x.txt", name: SECRET }] }],
    ["file uri", { files: [{ uri: `file:///project/${SECRET}.txt`, name: "x.txt" }] }],
    ["file description", { files: [{ uri: "file:///project/x.txt", description: SECRET }] }],
    [
      "file mention",
      {
        files: [
          {
            uri: "file:///project/x.txt",
            mention: { start: 0, end: 1, text: SECRET },
          },
        ],
      },
    ],
    ["agent name", { agents: [{ name: SECRET }] }],
    ["skill id", { skills: [{ id: SECRET, name: "safe" }] }],
    ["skill name", { skills: [{ id: "safe", name: SECRET }] }],
  ])("blocks a secret in %s", async (_label, attachments) => {
    const { hook } = createPromptHook(enabled)
    const output = {
      message: {},
      parts: [{ type: "text", text: "clean text" }],
      attachments,
    }

    await expect(hook({ sessionID: "s1", messageID: "m1" }, output)).rejects.toThrow(
      "blocked by security policy",
    )
  })

  test("data: URI content is not treated as attachment metadata", async () => {
    const { hook } = createPromptHook(enabled)
    const output = {
      message: {},
      parts: [{ type: "text", text: "clean text" }],
      attachments: {
        files: [{ uri: `data:text/plain;base64,${Buffer.from(SECRET).toString("base64")}` }],
      },
    }

    await expect(hook({ sessionID: "s1", messageID: "m1" }, output)).resolves.toBeUndefined()
  })

  test("attachment scanning stays off when scanUserPrompts is false", async () => {
    const { hook, sessionStats } = createPromptHook(DEFAULT_CONFIG)
    const output = {
      message: {},
      parts: [{ type: "text", text: "clean text" }],
      attachments: { files: [{ uri: "file:///project/x.txt", name: SECRET }] },
    }

    await expect(hook({ sessionID: "s1", messageID: "m1" }, output)).resolves.toBeUndefined()
    expect(sessionStats.getSummary().blockedAttempts).toBe(0)
  })

  test("attachment scanning is disabled by redactionEnabled=false", async () => {
    const { hook } = createPromptHook(
      config({ scanUserPrompts: true, redactionEnabled: false }),
    )
    const output = {
      message: {},
      parts: [{ type: "text", text: "clean text" }],
      attachments: { files: [{ uri: "file:///project/x.txt", name: SECRET }] },
    }

    await expect(hook({ sessionID: "s1", messageID: "m1" }, output)).resolves.toBeUndefined()
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Compaction outbound sanitation
// ─────────────────────────────────────────────────────────────────────────────

function makeCompactionHook(cfg: SecurityGuardConfig) {
  const scanner = createOutboundSanitizer({
    engine: createDetectionEngine(cfg),
    config: cfg,
    projectDir: "/project",
    policyText: POLICY,
    auditLogger: new AuditLogger({ ...DEFAULT_CONFIG.audit, enabled: false }),
    diagnosticLogger: null,
  })

  return createCompactionContext({
    config: cfg,
    diagnosticLogger: null,
    sanitizeRequest: (event) => scanner(event),
  })
}

function nativeCompactionEvent() {
  return {
    sessionID: "s1",
    agent: "build",
    model: { providerID: "test", modelID: "test" },
    system: [{ type: "text", text: `base system ${SECRET}` }],
    messages: [
      {
        role: "assistant",
        metadata: { keep: true },
        content: [
          {
            type: "text",
            text: `summary ${SECRET}`,
          },
          {
            type: "text",
            text: "signed clean text",
            providerMetadata: { thoughtSignature: "keep-me" },
          },
          {
            type: "tool-call",
            id: "call-1",
            name: "read",
            input: { path: "/project/app.ts" },
            providerMetadata: { native: "keep" },
          },
          {
            type: "tool-result",
            id: "call-1",
            result: { type: "content", value: [{ type: "text", text: `file ${SECRET}` }] },
          },
        ],
      },
    ],
    tools: { read: { description: "read", input: {} } },
    options: { temperature: 0.2 },
    metadata: { providerShape: { keep: true } },
  }
}

describe("compaction outbound sanitation", () => {
  test("redacts request text, appends policy, and preserves native metadata/provider shapes", async () => {
    const hook = makeCompactionHook(config())
    const event = nativeCompactionEvent()

    await hook(event)

    expect(event.system).toHaveLength(2)
    expect(event.system[0].text).toContain("[REDACTED]")
    expect(event.system[0].text).not.toContain(SECRET)
    expect(event.system[1]).toEqual({ type: "text", text: POLICY })

    const content = event.messages[0].content
    expect(content[0].text).toContain("[REDACTED]")
    expect(content[0].text).not.toContain(SECRET)
    expect(content[1]).toEqual({
      type: "text",
      text: "signed clean text",
      providerMetadata: { thoughtSignature: "keep-me" },
    })
    expect(content[2]).toEqual({
      type: "tool-call",
      id: "call-1",
      name: "read",
      input: { path: "/project/app.ts" },
      providerMetadata: { native: "keep" },
    })
    expect(content[3].result).toEqual({
      type: "content",
      value: [{ type: "text", text: "file [REDACTED]" }],
    })
    expect(event.messages[0].metadata).toEqual({ keep: true })
    expect(event.options).toEqual({ temperature: 0.2 })
    expect(event.metadata).toEqual({ providerShape: { keep: true } })
  })

  test("provider-signed text with a detection aborts instead of corrupting the signature", async () => {
    const hook = makeCompactionHook(config())
    const event = nativeCompactionEvent()
    event.messages[0].content[0] = {
      type: "text",
      text: `signed ${SECRET}`,
      providerMetadata: { signature: "sig" },
    }

    await expect(hook(event)).rejects.toThrow(
      /provider-native signed or encrypted data/,
    )
  })

  test("redactionEnabled=false still appends policy and leaves request text intact", async () => {
    const hook = makeCompactionHook(config({ redactionEnabled: false }))
    const event = nativeCompactionEvent()

    await hook(event)

    expect(event.system.some((part) => part.text === POLICY)).toBe(true)
    expect(event.system[0].text).toBe(`base system ${SECRET}`)
    expect(event.messages[0].content[0].text).toBe(`summary ${SECRET}`)
  })

  test("legacy string-sink callers still receive the policy only", async () => {
    const hook = createCompactionContext({
      config: config(),
      diagnosticLogger: null,
    })
    const output = { context: [] as string[] }

    await hook({}, output)

    expect(output.context).toHaveLength(1)
    expect(output.context[0]).toContain("## Warden Security Policy")
  })

  test("unsupported native shape throws instead of sending unsanitized history", async () => {
    const hook = makeCompactionHook(config())
    await expect(hook({ sessionID: "s1", system: [], messages: null })).rejects.toThrow(
      /compaction request shape is not supported/,
    )
  })

  test("scanner failure propagates (fail-closed)", async () => {
    const hook = createCompactionContext({
      config: config(),
      diagnosticLogger: null,
      sanitizeRequest: async () => {
        throw new Error("compaction scanner exploded")
      },
    })

    await expect(hook(nativeCompactionEvent())).rejects.toThrow(
      /compaction scanner exploded/,
    )
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Runtime compatibility diagnostic
// ─────────────────────────────────────────────────────────────────────────────

describe("runtime compatibility diagnostic", () => {
  test("declares the 2.0.18 host floor and the 2.0.29 typed-veto boundary", () => {
    expect(MIN_SUPPORTED_OPENCODE_VERSION).toBe("2.0.18")
    expect(TYPED_TOOL_VETO_OPENCODE_VERSION).toBe("2.0.29")
  })

  test("parses the supported 2.0.18 floor and rejects older runtimes", () => {
    expect(isRuntimeVersionSupported("2.0.18")).toBe(true)
    expect(isRuntimeVersionSupported("v2.0.18")).toBe(true)
    expect(isRuntimeVersionSupported("2.0.19")).toBe(true)
    expect(isRuntimeVersionSupported("2.1.3")).toBe(true)
    expect(isRuntimeVersionSupported("2.1.4")).toBe(true)
    expect(isRuntimeVersionSupported("2.2.0")).toBe(true)
    expect(isRuntimeVersionSupported("3.0.0")).toBe(true)
    expect(isRuntimeVersionSupported("2.0.17")).toBe(false)
    expect(isRuntimeVersionSupported("2.0.0")).toBe(false)
    expect(isRuntimeVersionSupported("1.3.0")).toBe(false)
    expect(isRuntimeVersionSupported("not-a-version")).toBeNull()
  })

  test("distinguishes the typed-veto boundary from the support floor", () => {
    expect(isTypedToolVetoSupported("2.0.18")).toBe(false)
    expect(isTypedToolVetoSupported("2.0.28")).toBe(false)
    expect(isTypedToolVetoSupported("2.0.29")).toBe(true)
    expect(isTypedToolVetoSupported("2.1.4")).toBe(true)
    expect(isTypedToolVetoSupported("garbage")).toBeNull()
  })

  test("warning is emitted only for a coherent version comparison", () => {
    expect(runtimeCompatibilityWarning("2.0.29")).toBeNull()
    expect(runtimeCompatibilityWarning("2.1.4")).toBeNull()
    expect(runtimeCompatibilityWarning("garbage")).toBeNull()

    // Supported floor, but before the typed Tool.Error veto mapping.
    expect(runtimeCompatibilityWarning("2.0.18")).toContain("2.0.18")
    expect(runtimeCompatibilityWarning("2.0.18")).toContain("2.0.29")
    expect(runtimeCompatibilityWarning("2.0.18")).toContain("untyped")
    expect(runtimeCompatibilityWarning("2.0.18")).toContain("remain installed")
    expect(runtimeCompatibilityWarning("2.0.18")).not.toContain("below the supported")

    // Below the support floor.
    expect(runtimeCompatibilityWarning("2.0.17")).toContain("below the supported runtime floor")
    expect(runtimeCompatibilityWarning("2.0.17")).toContain("2.0.18")
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// setup() wiring: warn, never refuse; lazy session-rule sync
// ─────────────────────────────────────────────────────────────────────────────

function makeFakeCtx(directory: string) {
  const hooks = new Map<string, { callback: (event: any) => any }>()
  const sessionPermissions = new Map<string, PermissionRule[]>()
  const updates: Array<{ sessionID: string; permissions: PermissionRule[] }> = []

  const domain = (name: string) => ({
    hook: async (hookName: string, callback: (event: any) => any) => {
      hooks.set(`${name}.${hookName}`, { callback })
      return { dispose: async () => undefined }
    },
  })

  const ctx = {
    app: { version: "2.0.18" },
    location: { directory },
    options: {
      notifications: false,
      audit: { enabled: false },
      diagnosticLog: { enabled: false },
      blockedTools: ["shell"],
      llm: { enabled: false },
    },
    permission: domain("permission"),
    shell: domain("shell"),
    session: {
      ...domain("session"),
      synthetic: async () => undefined,
      get: async ({ sessionID }: { sessionID: string }) => ({
        id: sessionID,
        permissions: sessionPermissions.get(sessionID),
      }),
      update: async ({
        sessionID,
        permissions,
      }: {
        sessionID: string
        permissions: PermissionRule[]
      }) => {
        updates.push({ sessionID, permissions: [...permissions] })
        sessionPermissions.set(sessionID, [...permissions])
      },
    },
    tool: {
      ...domain("tool"),
      transform: async () => ({ dispose: async () => undefined }),
    },
    event: {
      subscribe: () => (async function* () {})(),
    },
  }

  return { ctx, hooks, sessionPermissions, updates }
}

describe("setup() runtime diagnostic and lazy sync wiring", () => {
  test("warns about the typed-veto boundary at the 2.0.18 floor, keeps protections installed, and preserves host session rules", async () => {
    const directory = makeTempDir()
    process.env.HOME = makeTempDir()
    const warnings: string[] = []
    console.log = () => undefined
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(" "))
    }
    console.error = () => undefined

    const fake = makeFakeCtx(directory)
    const cleanup = await warden.setup(fake.ctx as any)

    try {
      expect(warnings.join("\n")).toContain("2.0.29")
      expect(warnings.join("\n")).toContain("remain installed")

      // Protections are installed at the supported floor despite the untyped
      // veto path.
      expect(fake.hooks.has("tool.execute.before")).toBe(true)
      expect(fake.hooks.has("permission.evaluate")).toBe(true)
      expect(fake.hooks.has("session.context")).toBe(true)

      const existing: PermissionRule = {
        action: "read",
        resource: "docs/*",
        effect: "allow",
      }
      fake.sessionPermissions.set("s1", [existing])

      await fake.hooks.get("tool.execute.before")!.callback({
        tool: "read",
        sessionID: "s1",
        id: "call-1",
        input: { path: join(directory, "app.ts") },
      })

      const update = fake.updates.find((entry) => entry.sessionID === "s1")
      expect(update).toBeDefined()
      expect(update!.permissions[0]).toEqual(existing)
      expect(update!.permissions).toContainEqual({
        action: "shell",
        resource: "*",
        effect: "deny",
      })

      // A second call reuses the sync; the host ruleset is not rewritten.
      await fake.hooks.get("tool.execute.before")!.callback({
        tool: "read",
        sessionID: "s1",
        id: "call-2",
        input: { path: join(directory, "app.ts") },
      })
      expect(fake.updates.filter((entry) => entry.sessionID === "s1")).toHaveLength(1)
    } finally {
      if (cleanup) await cleanup()
    }
  })
})
