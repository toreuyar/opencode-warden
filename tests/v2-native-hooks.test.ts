import { afterEach, describe, expect, test } from "bun:test"
import { existsSync, mkdtempSync, rmSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"
import warden from "../src/index.js"
import { createDetectionEngine } from "../src/detection/index.js"
import { AuditLogger } from "../src/audit/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import { createOutboundSanitizer, appendSecurityPolicy } from "../src/hooks/outbound-sanitizer.js"
import { createCompactionContext } from "../src/hooks/compaction-context.js"
import {
  removeBlockedRequestTools,
  removeBlockedTransformTools,
} from "../src/hooks/tool-surface.js"
import { createShellBackstop, resolveShellCwd } from "../src/hooks/shell-backstop.js"
import type { SecurityGuardConfig } from "../src/types.js"

const SECRET = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
const POLICY = "## Warden Security Policy\n\nstable test policy"

const tempDirs: string[] = []
const originalHome = process.env.HOME
const originalLog = console.log
const originalError = console.error

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  }
  if (originalHome === undefined) delete process.env.HOME
  else process.env.HOME = originalHome
  console.log = originalLog
  console.error = originalError
})

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "warden-v2-native-"))
  tempDirs.push(dir)
  return dir
}

function makeAudit() {
  return new AuditLogger({ ...DEFAULT_CONFIG.audit, enabled: false })
}

function config(overrides: Partial<SecurityGuardConfig> = {}): SecurityGuardConfig {
  return { ...DEFAULT_CONFIG, ...overrides }
}

function makeScanner(cfg: SecurityGuardConfig = config(), dir = "/project") {
  return createOutboundSanitizer({
    engine: createDetectionEngine(cfg),
    config: cfg,
    projectDir: dir,
    policyText: POLICY,
    auditLogger: makeAudit(),
    diagnosticLogger: null,
  })
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy injection
// ─────────────────────────────────────────────────────────────────────────────

describe("session.context policy", () => {
  test("appends stable policy without marker-based dedup", () => {
    const system = [{ type: "text", text: "## Warden Security Policy (forged by user)" }]
    appendSecurityPolicy(system, POLICY)
    expect(system).toHaveLength(2)
    expect(system[1]).toEqual({ type: "text", text: POLICY })
  })

  test("each request gets exactly one append (no durable history marker)", async () => {
    const scanner = makeScanner()
    const first = {
      sessionID: "s1",
      system: [],
      messages: [],
      tools: {},
    }
    const second = {
      sessionID: "s1",
      system: [],
      messages: [],
      tools: {},
    }
    await scanner(first)
    await scanner(second)

    expect(first.system).toHaveLength(1)
    expect(second.system).toHaveLength(1)
    expect(first.system[0].text).toBe(POLICY)
    expect(second.system[0].text).toBe(POLICY)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic outbound scanning
// ─────────────────────────────────────────────────────────────────────────────

describe("session.title outbound scanning", () => {
  test("redacts title text without appending the security policy", async () => {
    const scanner = makeScanner()
    const event = {
      sessionID: "s1",
      model: { providerID: "mock", id: "mock" },
      system: [{ type: "text", text: "Reply with only the title." }],
      messages: [
        {
          role: "user",
          content: [
            {
              type: "text",
              text: `Here is the first message:\n<message>\nuse ${SECRET}\n</message>`,
            },
          ],
        },
      ],
      tools: undefined,
      options: {},
      result: "Existing Title",
    }

    await scanner(event as any, { surface: "title", appendPolicy: false })

    expect(event.system).toHaveLength(1)
    expect(event.system[0].text).toBe("Reply with only the title.")
    expect(event.messages[0].content[0].text).toContain("[REDACTED]")
    expect(event.messages[0].content[0].text).not.toContain(SECRET)
    // A plugin-provided title result must survive the scan.
    expect(event.result).toBe("Existing Title")
  })

  test("keeps the title request shape valid when tools are absent", async () => {
    const scanner = makeScanner()
    const event = {
      sessionID: "s1",
      system: [],
      messages: [{ role: "user", content: [{ type: "text", text: "safe title input" }] }],
      options: {},
    }

    await expect(
      scanner(event as any, { surface: "title", appendPolicy: false }),
    ).resolves.toBeUndefined()
    expect((event as any).tools).toBeUndefined()
  })

  test("aborts rather than rewriting provider-signed title text", async () => {
    const scanner = makeScanner()
    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "user",
          content: [
            {
              type: "text",
              text: SECRET,
              providerMetadata: { provider: { signature: "signed" } },
            },
          ],
        },
      ],
      options: {},
    }

    await expect(
      scanner(event as any, { surface: "title", appendPolicy: false }),
    ).rejects.toThrow(/provider-native signed or encrypted/)
  })

  test("redactionEnabled=false leaves title text untouched and appends no policy", async () => {
    const scanner = makeScanner(config({ redactionEnabled: false }))
    const event = {
      sessionID: "s1",
      system: [],
      messages: [{ role: "user", content: [{ type: "text", text: SECRET }] }],
      options: {},
    }

    await scanner(event as any, { surface: "title", appendPolicy: false })

    expect(event.system).toHaveLength(0)
    expect(event.messages[0].content[0].text).toBe(SECRET)
  })

  test("scanner failure on a title request throws instead of sending raw text", async () => {
    const scanner = createOutboundSanitizer({
      engine: {
        scan() {
          throw new Error("scanner exploded")
        },
      } as any,
      config: config(),
      projectDir: "/project",
      policyText: POLICY,
      auditLogger: makeAudit(),
      diagnosticLogger: null,
    })
    const event = {
      sessionID: "s1",
      system: [],
      messages: [{ role: "user", content: [{ type: "text", text: SECRET }] }],
      options: {},
    }

    await expect(
      scanner(event as any, { surface: "title", appendPolicy: false }),
    ).rejects.toThrow(/scanner exploded/)
  })
})

describe("session.generate outbound scanning", () => {
  test("redacts generated-context text and appends the policy", async () => {
    const scanner = makeScanner()
    const event = {
      sessionID: "s1",
      system: [{ type: "text", text: `system ${SECRET}` }],
      messages: [
        { role: "user", content: [{ type: "text", text: `prompt ${SECRET}` }] },
        {
          role: "assistant",
          content: [
            { type: "tool-call", id: "call-1", name: "read", input: { path: "/project/app.ts" } },
            {
              type: "tool-result",
              id: "call-1",
              name: "read",
              result: { type: "text", value: `result ${SECRET}` },
            },
          ],
        },
      ],
      tools: { read: { description: "read", input: {} } },
    }

    await scanner(event as any, { surface: "generate" })

    expect(event.system).toHaveLength(2)
    expect(event.system[1].text).toBe(POLICY)
    expect(event.system[0].text).toContain("[REDACTED]")
    expect(event.messages[0].content[0].text).toContain("[REDACTED]")
    expect((event.messages[1].content[1] as any).result.value).toContain("[REDACTED]")
    expect((event.messages[1].content[0] as any).id).toBe("call-1")
    expect((event.messages[1].content[0] as any).name).toBe("read")
  })
})

describe("session.context outbound scanning", () => {
  test("redacts supported text channels while preserving tool pairing/native metadata", async () => {
    const scanner = makeScanner()
    const providerMetadata = { provider: { signature: "signed-original-text" } }
    const event = {
      sessionID: "s1",
      system: [{ type: "text", text: `system ${SECRET}` }],
      tools: {},
      messages: [
        {
          role: "user",
          content: [{ type: "text", text: `user ${SECRET}` }],
        },
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              id: "call-1",
              name: "read",
              input: { path: "/project/app.ts", note: "safe" },
              providerMetadata,
            },
            {
              type: "tool-result",
              id: "call-1",
              name: "read",
              result: { type: "text", value: "result clean" },
              providerMetadata,
            },
            { type: "reasoning", text: `reasoning ${SECRET}` },
            { type: "compaction", text: `summary ${SECRET}` },
          ],
        },
      ],
    }

    await scanner(event as any)

    expect(event.system[0].text).toContain("[REDACTED]")
    expect(event.system[0].text).not.toContain(SECRET)
    expect(event.messages[0].content[0].text).toContain("[REDACTED]")
    const content = event.messages[1].content as any[]
    // Tool-call input is deliberately not rewritten (pairing preservation).
    expect(content[0].input.note).toBe("safe")
    expect(content[0].id).toBe("call-1")
    expect(content[0].name).toBe("read")
    expect(content[0].providerMetadata).toEqual(providerMetadata)
    expect(content[1].result.value).toBe("result clean")
    expect(content[1].id).toBe("call-1")
    expect(content[1].providerMetadata).toEqual(providerMetadata)
    expect(content[2].text).toContain("[REDACTED]")
    expect(content[3].text).toContain("[REDACTED]")
  })

  test("redacts historical tool-call input values while preserving ids, names, keys, and structure", async () => {
    const scanner = makeScanner()
    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              id: "call-1",
              name: "write",
              input: {
                path: "/project/app.ts",
                content: `key ${SECRET}`,
                nested: { list: ["safe", SECRET], keep: 2 },
              },
            },
          ],
        },
      ],
      tools: {},
    }

    await scanner(event as any)

    const part = (event.messages[0].content as any[])[0]
    expect(part.id).toBe("call-1")
    expect(part.name).toBe("write")
    expect(Object.keys(part.input)).toEqual(["path", "content", "nested"])
    expect(part.input.path).toBe("/project/app.ts")
    expect(part.input.content).toContain("[REDACTED]")
    expect(part.input.content).not.toContain(SECRET)
    expect(part.input.nested.list[0]).toBe("safe")
    expect(part.input.nested.list[1]).toContain("[REDACTED]")
    expect(part.input.nested.keep).toBe(2)
  })

  test("redacts string-encoded JSON tool-call inputs without changing their representation", async () => {
    const scanner = makeScanner()
    const rawInput = JSON.stringify({
      path: "/project/app.ts",
      content: `key ${SECRET}`,
    })
    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            { type: "tool-call", id: "call-json", name: "write", input: rawInput },
          ],
        },
      ],
      tools: {},
    }

    await scanner(event as any)

    const part = (event.messages[0].content as any[])[0]
    expect(typeof part.input).toBe("string")
    expect(part.input).not.toContain(SECRET)
    expect(JSON.parse(part.input)).toEqual({
      path: "/project/app.ts",
      content: "key [REDACTED]",
    })
    expect(part.id).toBe("call-json")
    expect(part.name).toBe("write")
  })

  test("rejects provider-signed or encrypted tool-call inputs instead of rewriting them", async () => {
    for (const binding of [
      { providerMetadata: { provider: { signature: "sig" } } },
      { encrypted: "opaque-provider-bytes" },
    ]) {
      const scanner = makeScanner()
      const event = {
        sessionID: "s1",
        system: [],
        messages: [
          {
            role: "assistant",
            content: [
              {
                type: "tool-call",
                id: "call-1",
                name: "write",
                input: { path: "/project/app.ts", content: `key ${SECRET}` },
                ...binding,
              },
            ],
          },
        ],
        tools: {},
      }

      await expect(scanner(event as any)).rejects.toThrow(
        /provider-native signed or encrypted data/,
      )
    }
  })

  test("rejects a detection under a metadata-sensitive input key", async () => {
    const scanner = makeScanner()
    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              id: "call-1",
              name: "write",
              input: {
                path: "/project/app.ts",
                providerMetadata: { signature: SECRET },
              },
            },
          ],
        },
      ],
      tools: {},
    }

    await expect(scanner(event as any)).rejects.toThrow(
      /provider-native signed or encrypted data/,
    )
  })

  test("leaves clean metadata-sensitive input keys untouched", async () => {
    const scanner = makeScanner()
    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              id: "call-1",
              name: "write",
              input: {
                path: "/project/app.ts",
                providerMetadata: { signature: "opaque-native-value" },
              },
            },
          ],
        },
      ],
      tools: {},
    }

    await expect(scanner(event as any)).resolves.toBeUndefined()
    expect((event.messages[0].content as any[])[0].input.providerMetadata).toEqual({
      signature: "opaque-native-value",
    })
  })

  test("rejects cycles, excessive depth, and non-JSON tool-call input structures", async () => {
    const cases: unknown[] = []

    const cyclic: Record<string, unknown> = { path: "/project/app.ts" }
    cyclic.self = cyclic
    cyclic.content = `key ${SECRET}`
    cases.push(cyclic)

    let deep: any = { content: `key ${SECRET}` }
    for (let i = 0; i < 10; i++) deep = { nested: deep }
    cases.push(deep)

    cases.push({ path: "/project/app.ts", content: new Map([["k", SECRET]]) })

    for (const input of cases) {
      const scanner = makeScanner()
      const event = {
        sessionID: "s1",
        system: [],
        messages: [
          {
            role: "assistant",
            content: [{ type: "tool-call", id: "call-1", name: "write", input }],
          },
        ],
        tools: {},
      }
      await expect(scanner(event as any)).rejects.toThrow(
        /cannot safely rewrite without corrupting the request structure/,
      )
    }
  })

  test("rejects a detection in a tool-call argument key (keys are never renamed)", async () => {
    const scanner = makeScanner()
    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              id: "call-1",
              name: "read",
              input: { path: "/project/app.ts", [SECRET]: "value" },
            },
          ],
        },
      ],
      tools: {},
    }

    await expect(scanner(event as any)).rejects.toThrow(
      /cannot safely rewrite without corrupting the request structure/,
    )
  })

  test("honors redactionExemptPaths for write tool-call input", async () => {
    const cfg = config({ redactionExemptPaths: ["**/exempt.ts"] })
    const scanner = makeScanner(cfg, "/project")
    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              id: "call-write",
              name: "write",
              input: { path: "/project/exempt.ts", content: `key ${SECRET}` },
            },
          ],
        },
      ],
      tools: {},
    }

    await expect(scanner(event as any)).resolves.toBeUndefined()
    expect((event.messages[0].content as any[])[0].input.content).toBe(
      `key ${SECRET}`,
    )
  })

  test("redactOnWrite=false exempts historical write/edit/patch inputs", async () => {
    const scanner = makeScanner(config({ redactOnWrite: false }), "/project")
    const inputs = [
      { name: "write", input: { path: "/project/app.ts", content: `key ${SECRET}` } },
      {
        name: "edit",
        input: {
          path: "/project/app.ts",
          oldString: "safe",
          newString: `key ${SECRET}`,
        },
      },
      {
        name: "patch",
        input: {
          patchText: `*** Begin Patch\n*** Update File: /project/app.ts\n+key ${SECRET}\n*** End Patch`,
        },
      },
    ]

    for (const [index, { name, input }] of inputs.entries()) {
      const event = {
        sessionID: "s1",
        system: [],
        messages: [
          {
            role: "assistant",
            content: [
              { type: "tool-call", id: `call-${index}`, name, input },
            ],
          },
        ],
        tools: {},
      }

      await expect(scanner(event as any)).resolves.toBeUndefined()
      const part = (event.messages[0].content as any[])[0]
      expect(JSON.stringify(part.input)).toContain(SECRET)
    }
  })

  test("redactOnWrite=true redacts historical write/edit/patch inputs in the request projection", async () => {
    const scanner = makeScanner(config({ redactOnWrite: true }), "/project")
    const inputs = [
      { name: "write", input: { path: "/project/app.ts", content: `key ${SECRET}` } },
      {
        name: "edit",
        input: {
          path: "/project/app.ts",
          oldString: "safe",
          newString: `key ${SECRET}`,
        },
      },
      {
        name: "patch",
        input: {
          patchText: `*** Begin Patch\n*** Update File: /project/app.ts\n+key ${SECRET}\n*** End Patch`,
        },
      },
    ]

    for (const [index, { name, input }] of inputs.entries()) {
      const event = {
        sessionID: "s1",
        system: [],
        messages: [
          {
            role: "assistant",
            content: [
              { type: "tool-call", id: `call-${index}`, name, input },
            ],
          },
        ],
        tools: {},
      }

      await expect(scanner(event as any)).resolves.toBeUndefined()
      const part = (event.messages[0].content as any[])[0]
      expect(part.id).toBe(`call-${index}`)
      expect(part.name).toBe(name)
      expect(JSON.stringify(part.input)).not.toContain(SECRET)
      expect(JSON.stringify(part.input)).toContain("[REDACTED]")
      expect(Object.keys(part.input)).toEqual(Object.keys(input))
    }
  })

  test("redactOnWrite=false does not exempt historical shell inputs from redaction", async () => {
    const scanner = makeScanner(config({ redactOnWrite: false }), "/project")
    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              id: "call-shell",
              name: "shell",
              input: { command: `echo ${SECRET} > /project/app.ts` },
            },
          ],
        },
      ],
      tools: {},
    }

    await expect(scanner(event as any)).resolves.toBeUndefined()
    const part = (event.messages[0].content as any[])[0]
    expect(part.input.command).not.toContain(SECRET)
    expect(part.input.command).toContain("[REDACTED]")
    expect(part.id).toBe("call-shell")
    expect(part.name).toBe("shell")
  })

  test("compaction applies the same redactOnWrite exemption and shell gate", async () => {
    const cfg = config({ redactOnWrite: false })
    const scanner = makeScanner(cfg, "/project")
    const compaction = createCompactionContext({
      config: cfg,
      diagnosticLogger: null,
      sanitizeRequest: scanner,
    })

    const exemptEvent = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              id: "call-write",
              name: "write",
              input: { path: "/project/app.ts", content: `key ${SECRET}` },
            },
          ],
        },
      ],
      tools: {},
    }
    await expect(compaction(exemptEvent as any)).resolves.toBeUndefined()

    const shellEvent = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              id: "call-shell",
              name: "shell",
              input: { command: `echo ${SECRET} > /project/app.ts` },
            },
          ],
        },
      ],
      tools: {},
    }
    await expect(compaction(shellEvent as any)).resolves.toBeUndefined()
    const shellPart = (shellEvent.messages[0].content as any[])[0]
    expect(shellPart.input.command).not.toContain(SECRET)
    expect(shellPart.input.command).toContain("[REDACTED]")

    // Non-write tool-call inputs are still redacted under redactOnWrite=false.
    const replayEvent = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              id: "call-replay",
              name: "read",
              input: { path: "/project/app.ts", note: `key ${SECRET}` },
            },
            {
              type: "tool-result",
              id: "call-replay",
              name: "read",
              result: { type: "text", value: "Read file successfully" },
            },
          ],
        },
      ],
      tools: {},
    }
    await expect(compaction(replayEvent as any)).resolves.toBeUndefined()
    const [call, result] = replayEvent.messages[0].content as any[]
    expect(call.id).toBe("call-replay")
    expect(call.name).toBe("read")
    expect(call.input.note).not.toContain(SECRET)
    expect(call.input.note).toContain("[REDACTED]")
    expect(result.id).toBe("call-replay")
    expect(result.result.value).toBe("Read file successfully")
  })

  test("does not rewrite provider-signed text when redaction would be required", async () => {
    const scanner = makeScanner()
    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "text",
              text: `signed ${SECRET}`,
              providerMetadata: { provider: { signature: "sig" } },
            },
          ],
        },
      ],
      tools: {},
    }

    await expect(scanner(event as any)).rejects.toThrow(
      /provider-native signed or encrypted data/,
    )
  })

  test("provider-signed clean text passes through unchanged", async () => {
    const scanner = makeScanner()
    const providerMetadata = { provider: { signature: "sig" } }
    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [{ type: "text", text: "clean signed text", providerMetadata }],
        },
      ],
      tools: {},
    }

    await scanner(event as any)
    expect(event.messages[0].content[0]).toEqual({
      type: "text",
      text: "clean signed text",
      providerMetadata,
    })
  })

  test("redacts JSON tool-result string leaves without rewriting ids", async () => {
    const scanner = makeScanner()
    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "tool",
          content: [
            {
              type: "tool-call",
              id: "call-json",
              name: "read",
              input: { path: "/project/app.ts" },
            },
            {
              type: "tool-result",
              id: "call-json",
              name: "read",
              result: {
                type: "json",
                value: { token: SECRET, nested: { value: SECRET }, keep: 2 },
              },
            },
          ],
        },
      ],
      tools: {},
    }

    await scanner(event as any)

    const result = (event.messages[0].content as any[])[1]
    expect(JSON.stringify(result.result.value)).not.toContain(SECRET)
    expect(result.result.value.keep).toBe(2)
    expect(result.id).toBe("call-json")
  })

  test("honors redactionExemptPaths for attributable reads and shell reads", async () => {
    const cfg = config({ redactionExemptPaths: ["**/exempt.ts"] })
    const scanner = makeScanner(cfg, "/project")

    const event = {
      sessionID: "s1",
      system: [],
      messages: [
        {
          role: "assistant",
          content: [
            { type: "tool-call", id: "read-exempt", name: "read", input: { path: "/project/exempt.ts" } },
            {
              type: "tool-result",
              id: "read-exempt",
              name: "read",
              result: { type: "text", value: `key ${SECRET}` },
            },
            { type: "tool-call", id: "read-other", name: "read", input: { path: "/project/app.ts" } },
            {
              type: "tool-result",
              id: "read-other",
              name: "read",
              result: { type: "text", value: `key ${SECRET}` },
            },
            {
              type: "tool-call",
              id: "shell-exempt",
              name: "shell",
              input: { command: "cat /project/exempt.ts" },
            },
            {
              type: "tool-result",
              id: "shell-exempt",
              name: "shell",
              result: { type: "text", value: `key ${SECRET}` },
            },
          ],
        },
      ],
      tools: {},
    }

    await scanner(event as any)

    const content = event.messages[0].content as any[]
    expect(content[1].result.value).toBe(`key ${SECRET}`)
    expect(content[3].result.value).toContain("[REDACTED]")
    expect(content[5].result.value).toBe(`key ${SECRET}`)
  })

  test("redactionEnabled=false skips scanning but still appends policy", async () => {
    const scanner = makeScanner(config({ redactionEnabled: false }))
    const event = {
      sessionID: "s1",
      system: [],
      messages: [{ role: "user", content: [{ type: "text", text: SECRET }] }],
      tools: {},
    }

    await scanner(event as any)

    expect(event.system).toHaveLength(1)
    expect(event.messages[0].content[0].text).toBe(SECRET)
  })

  test("scanner failure throws instead of falling back to raw text", async () => {
    const scanner = createOutboundSanitizer({
      engine: {
        scan() {
          throw new Error("scanner exploded")
        },
      } as any,
      config: config(),
      projectDir: "/project",
      policyText: POLICY,
      auditLogger: makeAudit(),
      diagnosticLogger: null,
    })
    const event = {
      sessionID: "s1",
      system: [{ type: "text", text: SECRET }],
      messages: [],
      tools: {},
    }

    await expect(scanner(event as any)).rejects.toThrow(/scanner exploded/)
  })

  test("unsupported request shape throws (fail closed)", async () => {
    const scanner = makeScanner()
    await expect(scanner({ sessionID: "s1", system: [], messages: null, tools: {} } as any))
      .rejects.toThrow(/outbound request shape is not supported/)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Tool-surface removal
// ─────────────────────────────────────────────────────────────────────────────

describe("blockedTools surface removal", () => {
  test("removes per-request tools alias-aware by advertised key", () => {
    const tools = {
      shell: { description: "shell", input: {} },
      bash: { description: "bash", input: {} },
      subagent: { description: "subagent", input: {} },
      task: { description: "task", input: {} },
      read: { description: "read", input: {} },
      "my-tool": { description: "custom", input: {} },
    }

    const removed = removeBlockedRequestTools(tools, config({ blockedTools: ["shell", "task"] }))

    expect(removed.sort()).toEqual(["bash", "shell", "subagent", "task"])
    expect(Object.keys(tools)).toEqual(["read", "my-tool"])
  })

  test("transform removal uses actual effective ids, including namespaces", () => {
    const removedIds: string[] = []
    const editor = {
      list: () => [
        { id: "shell", name: "shell" },
        { id: "bash", name: "bash" },
        { id: "team_task", name: "task" },
        { id: "read", name: "read" },
      ],
      remove: (id: string) => {
        removedIds.push(id)
      },
    }

    const removed = removeBlockedTransformTools(
      editor,
      config({ blockedTools: ["shell", "subagent"] }),
    )

    expect(removedIds).toEqual(["shell", "bash", "team_task"])
    expect(removed).toEqual(removedIds)
  })

  test("no blocked tools means no removal", () => {
    const removedIds: string[] = []
    const editor = {
      list: () => [{ id: "shell", name: "shell" }],
      remove: (id: string) => {
        removedIds.push(id)
      },
    }

    expect(removeBlockedTransformTools(editor, config({ blockedTools: [] }))).toEqual([])
    expect(removedIds).toEqual([])
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Global shell backstop
// ─────────────────────────────────────────────────────────────────────────────

describe("global shell backstop", () => {
  test("resolves relative cwd against the location directory", () => {
    expect(resolveShellCwd("/project", "sub/dir")).toBe("/project/sub/dir")
    expect(resolveShellCwd("/project", "/absolute")).toBe("/absolute")
    expect(resolveShellCwd("/project", "")).toBe("/project")
  })

  test("blocks relative blocked read/write targets using the actual cwd", async () => {
    const directory = makeTempDir()
    const backstop = createShellBackstop({
      config: config(),
      projectDir: directory,
      auditLogger: makeAudit(),
      diagnosticLogger: null,
    })

    await expect(backstop({ command: "cat .env", cwd: directory })).rejects.toThrow(
      /Security Guard: shell read/,
    )
    await expect(backstop({ command: "echo x > .env", cwd: directory })).rejects.toThrow(
      /Security Guard: shell write/,
    )
    await expect(
      backstop({ command: "cat ../.env", cwd: join(directory, "sub") }),
    ).rejects.toThrow(/Security Guard: shell read/)
  })

  test("write-protected paths are writable-blocked but readable", async () => {
    const directory = makeTempDir()
    const backstop = createShellBackstop({
      config: config(),
      projectDir: directory,
      auditLogger: makeAudit(),
      diagnosticLogger: null,
    })

    await expect(
      backstop({ command: "truncate -s 0 /var/log/syslog", cwd: directory }),
    ).rejects.toThrow(/Security Guard: shell write/)
    await expect(
      backstop({ command: "echo x > /var/log/syslog", cwd: directory }),
    ).rejects.toThrow(/Security Guard: shell write/)
    await expect(
      backstop({ command: "cat /var/log/syslog", cwd: directory }),
    ).resolves.toBeUndefined()
  })

  test("whitelist wins over the blocklist", async () => {
    const directory = makeTempDir()
    const backstop = createShellBackstop({
      config: config({ whitelistedPaths: [join(directory, ".env")] }),
      projectDir: directory,
      auditLogger: makeAudit(),
      diagnosticLogger: null,
    })

    await expect(backstop({ command: "cat .env", cwd: directory })).resolves.toBeUndefined()
  })

  test("blocks remote protected paths without a session id", async () => {
    const directory = makeTempDir()
    const backstop = createShellBackstop({
      config: config(),
      projectDir: directory,
      auditLogger: makeAudit(),
      diagnosticLogger: null,
    })

    await expect(
      backstop({ command: "scp host:/etc/server.pem ./", cwd: directory }),
    ).rejects.toThrow(/remote shell read/)
  })

  test("skips dynamic targets (agent path is already fail-closed upstream)", async () => {
    const directory = makeTempDir()
    const backstop = createShellBackstop({
      config: config(),
      projectDir: directory,
      auditLogger: makeAudit(),
      diagnosticLogger: null,
    })

    await expect(
      backstop({ command: "cat $HOME/.env", cwd: directory }),
    ).resolves.toBeUndefined()
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// setup() wiring (LLM disabled)
// ─────────────────────────────────────────────────────────────────────────────

interface FakeHookCall {
  readonly callback: (event: any) => any
}

function makeFakeCtx(directory: string) {
  const hooks = new Map<string, FakeHookCall>()
  const transforms: Array<(editor: any) => void> = []
  const calls = { synthetic: 0 }
  let fetchCalls = 0
  const originalFetch = globalThis.fetch
  globalThis.fetch = (async () => {
    fetchCalls++
    throw new Error("network disabled in test")
  }) as any

  const domain = (name: string) => ({
    hook: async (hookName: string, callback: (event: any) => any) => {
      hooks.set(`${name}.${hookName}`, { callback })
      return { dispose: async () => undefined }
    },
  })

  const ctx = {
    location: { directory },
    options: {
      notifications: false,
      audit: { enabled: false },
      diagnosticLog: { enabled: false },
      blockedTools: ["shell", "task"],
      llm: { enabled: false },
    },
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
      transform: async (callback: (editor: any) => void) => {
        transforms.push(callback)
        return { dispose: async () => undefined }
      },
    },
    event: {
      subscribe: () => (async function* () {})()
    },
  }

  return {
    ctx,
    hooks,
    transforms,
    calls,
    restoreFetch: () => {
      globalThis.fetch = originalFetch
    },
    getFetchCalls: () => fetchCalls,
  }
}

describe("setup() native V2 enforcement (LLM disabled)", () => {
  test("wires context policy/scanning, tool removal, and shell backstop without synthetic history", async () => {
    const directory = makeTempDir()
    process.env.HOME = makeTempDir()
    console.log = () => undefined
    console.error = () => undefined

    const fake = makeFakeCtx(directory)
    const cleanup = await warden.setup(fake.ctx as any)

    try {
      expect(fake.getFetchCalls()).toBe(0)
      expect(fake.hooks.has("session.context")).toBe(true)
      expect(fake.hooks.has("session.title")).toBe(true)
      expect(fake.hooks.has("session.generate")).toBe(true)
      expect(fake.hooks.has("shell.create.before")).toBe(true)
      expect(fake.hooks.has("tool.execute.before")).toBe(true)
      expect(fake.transforms).toHaveLength(1)

      // Transform removes blocked tools by effective id, alias-aware.
      const removed: string[] = []
      fake.transforms[0]({
        add: () => undefined,
        list: () => [
          { id: "shell", name: "shell" },
          { id: "bash", name: "bash" },
          { id: "team_task", name: "task" },
          { id: "read", name: "read" },
        ],
        remove: (id: string) => {
          removed.push(id)
        },
      })
      expect(removed).toEqual(["shell", "bash", "team_task"])

      // Per-request tools + policy + outbound redaction.
      const contextEvent = {
        sessionID: "s1",
        agent: "build",
        system: [{ type: "text", text: "base system" }],
        messages: [{ role: "user", content: [{ type: "text", text: SECRET }] }],
        tools: {
          shell: { description: "shell", input: {} },
          bash: { description: "bash", input: {} },
          task: { description: "task", input: {} },
          subagent: { description: "subagent", input: {} },
          read: { description: "read", input: {} },
        },
      }
      await fake.hooks.get("session.context")!.callback(contextEvent)
      expect(Object.keys(contextEvent.tools)).toEqual(["read"])
      expect(contextEvent.system).toHaveLength(2)
      expect(contextEvent.system[1].text).toContain("## Warden Security Policy")
      expect(contextEvent.messages[0].content[0].text).toContain("[REDACTED]")
      expect(contextEvent.messages[0].content[0].text).not.toContain(SECRET)

      // Title requests are tool-less and must be redacted without policy
      // injection (policy text can change the naming task).
      const titleEvent = {
        sessionID: "s1",
        system: [{ type: "text", text: "Reply with only the title." }],
        messages: [{ role: "user", content: [{ type: "text", text: SECRET }] }],
        options: {},
        result: "Title From Host",
      }
      await fake.hooks.get("session.title")!.callback(titleEvent)
      expect(titleEvent.system).toHaveLength(1)
      expect(titleEvent.system[0].text).toBe("Reply with only the title.")
      expect(titleEvent.messages[0].content[0].text).toContain("[REDACTED]")
      expect(titleEvent.messages[0].content[0].text).not.toContain(SECRET)
      expect(titleEvent.result).toBe("Title From Host")

      // Generate requests are full agent contexts: policy, redaction, and
      // blocked-tool removal all apply.
      const generateEvent = {
        sessionID: "s1",
        agent: "build",
        system: [{ type: "text", text: "base system" }],
        messages: [{ role: "user", content: [{ type: "text", text: SECRET }] }],
        tools: {
          shell: { description: "shell", input: {} },
          read: { description: "read", input: {} },
        },
      }
      await fake.hooks.get("session.generate")!.callback(generateEvent)
      expect(Object.keys(generateEvent.tools)).toEqual(["read"])
      expect(generateEvent.system).toHaveLength(2)
      expect(generateEvent.system[1].text).toContain("## Warden Security Policy")
      expect(generateEvent.messages[0].content[0].text).toContain("[REDACTED]")
      expect(generateEvent.messages[0].content[0].text).not.toContain(SECRET)

      // execute.before no longer injects a synthetic message.
      await fake.hooks.get("tool.execute.before")!.callback({
        tool: "read",
        sessionID: "s1",
        id: "call-1",
        input: { path: join(directory, "app.ts") },
      })
      expect(fake.calls.synthetic).toBe(0)

      // Global shell backstop blocks, then env stripping still runs for clean
      // commands. The shell event has no session identity.
      const shell = fake.hooks.get("shell.create.before")!.callback
      await expect(
        shell({
          command: `cat ${join(directory, ".env")}`,
          cwd: directory,
          timeout: 0,
          shell: "bash",
          env: {},
        }),
      ).rejects.toThrow(/Security Guard: shell read/)

      const cleanShell = {
        command: "echo hi",
        cwd: directory,
        timeout: 0,
        shell: "bash",
        env: { MY_SECRET: "value" },
      }
      await shell(cleanShell)
      expect(cleanShell.env.MY_SECRET).toBe("[REDACTED]")
    } finally {
      fake.restoreFetch()
      if (cleanup) await cleanup()
    }
  })
})
