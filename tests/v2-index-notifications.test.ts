import { afterEach, describe, expect, test } from "bun:test"
import { existsSync, mkdtempSync, rmSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"
import warden from "../src/index.js"
import { WARDEN_NOTIFICATION_EVENT } from "../src/rpc.js"

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
  const dir = mkdtempSync(join(tmpdir(), "warden-v2-index-notify-"))
  tempDirs.push(dir)
  return dir
}

function silenceConsole(): void {
  console.log = () => undefined
  console.warn = () => undefined
  console.error = () => undefined
}

const settle = () => new Promise<void>((resolve) => setTimeout(resolve, 0))

interface FakeRpc {
  rpc: {
    register: () => Promise<{
      events: { emit: (event: string, data: unknown) => Promise<void> }
      dispose: () => Promise<void>
    }>
  }
  emitted: Array<{ event: string; data: unknown }>
  readonly disposed: number
}

function makeFakeRpc(options: { failRegister?: boolean } = {}): FakeRpc {
  const emitted: Array<{ event: string; data: unknown }> = []
  let disposed = 0
  const rpc = {
    async register() {
      if (options.failRegister) throw new Error("rpc unavailable")
      return {
        events: {
          async emit(event: string, data: unknown) {
            emitted.push({ event, data })
          },
        },
        async dispose() {
          disposed += 1
        },
      }
    },
  }
  return {
    rpc,
    emitted,
    get disposed() {
      return disposed
    },
  }
}

function makeFakeCtx(options: unknown, directory: string, rpc = makeFakeRpc()) {
  const hooks = new Map<string, (event: any) => any>()
  const calls = { transforms: 0, subscribe: 0 }

  const domain = (name: string) => ({
    hook: async (hookName: string, callback: (event: any) => any) => {
      hooks.set(`${name}.${hookName}`, callback)
      return { dispose: async () => undefined }
    },
  })

  const ctx = {
    app: { version: "2.1.4" },
    location: { directory },
    options,
    rpc: rpc.rpc,
    permission: domain("permission"),
    shell: domain("shell"),
    session: {
      ...domain("session"),
      synthetic: async () => undefined,
      get: async () => ({ permissions: [] }),
      update: async () => undefined,
    },
    tool: {
      ...domain("tool"),
      transform: async () => {
        calls.transforms++
        return { dispose: async () => undefined }
      },
    },
    event: {
      subscribe: () => {
        calls.subscribe++
        return (async function* () {})()
      },
    },
  }

  return { ctx, hooks, calls, rpc }
}

const VALID_INLINE = {
  notifications: true,
  audit: { enabled: false },
  diagnosticLog: { enabled: false },
  blockedTools: ["shell"],
  llm: { enabled: false },
}

describe("index notification wiring", () => {
  test("vetoes an agent shell sequence but leaves the global path backstop unchanged", async () => {
    silenceConsole()
    process.env.HOME = makeTempDir()
    const directory = makeTempDir()
    const fake = makeFakeCtx({ ...VALID_INLINE, blockedTools: [] }, directory)
    const cleanup = await warden.setup(fake.ctx as any)

    try {
      const command = "git status; git diff"
      await expect(fake.hooks.get("tool.execute.before")!({
        tool: "shell",
        sessionID: "s1",
        id: "call-1",
        input: { command },
      })).rejects.toThrow(/Multiple sequential shell operations/)
      await fake.hooks.get("shell.create.before")!({ command, cwd: directory, env: {} })
    } finally {
      if (cleanup) await cleanup()
    }
  })

  test("routes hook toasts through the RPC bridge after config loads", async () => {
    silenceConsole()
    process.env.HOME = makeTempDir()
    const directory = makeTempDir()
    const fake = makeFakeCtx(VALID_INLINE, directory)
    const cleanup = await warden.setup(fake.ctx as any)

    try {
      await expect(
        fake.hooks.get("tool.execute.before")!({
          tool: "shell",
          sessionID: "s1",
          id: "call-1",
          input: { command: "echo /home/user/.env" },
        }),
      ).rejects.toThrow(/blocked by security policy/)

      await settle()
      expect(fake.rpc.emitted).toEqual([
        {
          event: WARDEN_NOTIFICATION_EVENT,
          data: { version: 1, kind: "blocked" },
        },
      ])
      expect(JSON.stringify(fake.rpc.emitted)).not.toContain("/home/user/.env")
    } finally {
      if (cleanup) await cleanup()
    }
  })

  test("notifications:false suppresses hook notifications", async () => {
    silenceConsole()
    process.env.HOME = makeTempDir()
    const directory = makeTempDir()
    const fake = makeFakeCtx({ ...VALID_INLINE, notifications: false }, directory)
    const cleanup = await warden.setup(fake.ctx as any)

    try {
      await expect(
        fake.hooks.get("tool.execute.before")!({
          tool: "shell",
          sessionID: "s1",
          id: "call-1",
          input: { command: "echo hi" },
        }),
      ).rejects.toThrow(/blocked by security policy/)

      await settle()
      expect(fake.rpc.emitted).toHaveLength(0)
    } finally {
      if (cleanup) await cleanup()
    }
  })

  test("config failure disposes the notification bridge and installs lockdown hooks", async () => {
    silenceConsole()
    process.env.HOME = makeTempDir()
    const directory = makeTempDir()
    const fake = makeFakeCtx({ llm: { enabled: "yes" } }, directory)
    const cleanup = await warden.setup(fake.ctx as any)

    try {
      await settle()
      expect(fake.rpc.disposed).toBe(1)
      expect(fake.rpc.emitted).toHaveLength(0)
      expect(fake.hooks.has("permission.evaluate")).toBe(true)
      expect(fake.hooks.has("tool.execute.before")).toBe(true)
      expect(fake.hooks.has("session.context")).toBe(true)
      expect(fake.calls.transforms).toBe(0)
    } finally {
      if (cleanup) await cleanup()
    }
  })

  test("unexpected setup exception installs the fail-closed lockdown instead of dropping the plugin", async () => {
    silenceConsole()
    process.env.HOME = makeTempDir()
    const directory = makeTempDir()
    const fake = makeFakeCtx(VALID_INLINE, directory)
    fake.ctx.tool.transform = async () => {
      throw new Error("transform failed")
    }

    const cleanup = await warden.setup(fake.ctx as any)

    try {
      await settle()
      // The notification bridge is disposed and no normal tools were added.
      expect(fake.rpc.disposed).toBe(1)
      expect(fake.calls.transforms).toBe(0)

      // The lockdown replaces/overrides the normal hooks.
      const permission = {
        sessionID: "s1",
        action: "read",
        resources: ["/project/.env"],
        effect: "allow" as const,
      }
      await fake.hooks.get("permission.evaluate")!(permission)
      expect(permission.effect).toBe("deny")
      expect(() => fake.hooks.get("tool.execute.before")!({})).toThrow(
        /Security Guard: Warden configuration is invalid/,
      )
      expect(() => fake.hooks.get("session.context")!({})).toThrow(
        /Security Guard: Warden configuration is invalid/,
      )
    } finally {
      if (cleanup) await cleanup()
    }
  })

  test("cleanup disposes the notification bridge", async () => {
    silenceConsole()
    process.env.HOME = makeTempDir()
    const directory = makeTempDir()
    const fake = makeFakeCtx(VALID_INLINE, directory)
    const cleanup = await warden.setup(fake.ctx as any)
    await settle()
    expect(fake.rpc.disposed).toBe(0)

    await cleanup?.()
    expect(fake.rpc.disposed).toBe(1)
  })
})
