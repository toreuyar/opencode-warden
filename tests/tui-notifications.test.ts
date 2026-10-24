import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { Rpc } from "@opencode/plugin/rpc"
import {
  sanitizeWardenNotification,
  WARDEN_NOTIFICATION_EVENT,
  WARDEN_NOTIFICATION_RPC_ID,
  WardenNotificationDefinition,
  wardenNotificationSchema,
} from "../src/rpc.js"
import {
  createWardenNotificationBridge,
  notificationFromLegacyToast,
} from "../src/tui-notifications.js"
import {
  registerWardenTuiNotifications,
  toastForWardenNotification,
} from "../src/tui.js"

describe("Warden notification RPC contract", () => {
  test("is a valid portable event-only definition", () => {
    expect(() => Rpc.define(WardenNotificationDefinition)).not.toThrow()
    expect(WardenNotificationDefinition.id).toBe(WARDEN_NOTIFICATION_RPC_ID)
    expect(WardenNotificationDefinition.events).toHaveProperty(WARDEN_NOTIFICATION_EVENT)
    expect(Object.keys(WardenNotificationDefinition.methods)).toHaveLength(0)
    expect(`rpc.${WardenNotificationDefinition.id}.${WARDEN_NOTIFICATION_EVENT}`)
      .toBe("rpc.opencode-warden.notifications.notification")
  })

  test("event schema implements the Standard Schema validation used by RPC emit", async () => {
    const schema = WardenNotificationDefinition.events[WARDEN_NOTIFICATION_EVENT].schema
    const accepted = await schema["~standard"].validate({
      version: 1,
      kind: "blocked",
      tool: "shell",
    })
    expect(accepted.issues).toBeUndefined()
    expect(accepted.value).toEqual({ version: 1, kind: "blocked", tool: "shell" })

    const rejected = await schema["~standard"].validate({
      version: 1,
      kind: "blocked",
      message: "sk-live-raw-payload",
    })
    expect(rejected.issues?.length ?? 0).toBeGreaterThan(0)
  })

  test("accepts only the strict, bounded event shape", () => {
    expect(
      wardenNotificationSchema.safeParse({
        version: 1,
        kind: "redacted",
        tool: "shell",
        count: 3,
      }).success,
    ).toBe(true)

    expect(
      wardenNotificationSchema.safeParse({
        version: 1,
        kind: "blocked",
        message: "secret sk-live-raw-payload",
      }).success,
    ).toBe(false)

    expect(
      wardenNotificationSchema.safeParse({
        version: 1,
        kind: "blocked",
        tool: "../.env",
      }).success,
    ).toBe(false)

    expect(
      wardenNotificationSchema.safeParse({ version: 1, kind: "made-up" }).success,
    ).toBe(false)
  })

  test("sanitizer drops unsafe optional fields and clamps the count", () => {
    expect(
      sanitizeWardenNotification({
        version: 99,
        kind: "blocked",
        tool: "bad tool\u001b[31m",
        count: 5_000_000,
      }),
    ).toEqual({ version: 1, kind: "blocked", count: 1_000_000 })

    expect(
      sanitizeWardenNotification({ kind: "redacted", tool: "mcp__server__read", count: 2.9 }),
    ).toEqual({ version: 1, kind: "redacted", tool: "mcp__server__read", count: 2 })

    expect(sanitizeWardenNotification({ kind: "unknown" })).toBeNull()
    expect(sanitizeWardenNotification(null)).toBeNull()
  })
})

describe("Server notification bridge", () => {
  const settle = () => new Promise<void>((resolve) => setTimeout(resolve, 0))

  function fakeRpc(options: { failRegister?: boolean; failEmit?: boolean } = {}) {
    const emitted: Array<{ event: string; data: unknown }> = []
    let disposed = 0
    const rpc = {
      async register(definition: typeof WardenNotificationDefinition) {
        if (options.failRegister) throw new Error("rpc unavailable")
        expect(definition.id).toBe(WARDEN_NOTIFICATION_RPC_ID)
        return {
          events: {
            async emit(event: string, data: unknown) {
              if (options.failEmit) throw new Error("client disconnected")
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

  test("emits sanitized structured events and honors live enablement", async () => {
    const fake = fakeRpc()
    let enabled = false
    const bridge = createWardenNotificationBridge({
      rpc: fake.rpc as never,
      enabled: () => enabled,
    })
    expect(bridge.ready).toBe(false)
    await settle()
    expect(bridge.ready).toBe(true)

    await bridge.notify({ kind: "blocked", tool: "shell" })
    expect(fake.emitted).toHaveLength(0)

    enabled = true
    await bridge.notify({ kind: "redacted", tool: "read", count: 4 })
    expect(fake.emitted).toEqual([
      {
        event: WARDEN_NOTIFICATION_EVENT,
        data: { version: 1, kind: "redacted", tool: "read", count: 4 },
      },
    ])

    await bridge.dispose()
    expect(fake.disposed).toBe(1)
    expect(bridge.ready).toBe(false)
  })

  test("does not block setup and flushes a bounded pre-ready queue", async () => {
    const emitted: Array<{ event: string; data: unknown }> = []
    let release!: () => void
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    let disposed = 0
    const rpc = {
      async register() {
        await gate
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

    const bridge = createWardenNotificationBridge({ rpc: rpc as never })
    expect(bridge.ready).toBe(false)
    await expect(bridge.showToast({ body: { message: "🛡 Blocked: path" } })).resolves.toBeUndefined()
    expect(emitted).toHaveLength(0)

    release()
    await settle()
    expect(bridge.ready).toBe(true)
    expect(emitted).toEqual([
      { event: WARDEN_NOTIFICATION_EVENT, data: { version: 1, kind: "blocked" } },
    ])

    await bridge.dispose()
    expect(disposed).toBe(1)
  })

  test("legacy toast text and raw payloads never reach the event stream", async () => {
    const fake = fakeRpc()
    const bridge = createWardenNotificationBridge({ rpc: fake.rpc as never })
    await settle()

    await bridge.showToast({
      body: {
        message: "🛡 Blocked: /home/user/.env with sk-live-raw-payload",
        variant: "error",
      },
    })
    await bridge.showToast({
      body: {
        message: "🛡 Warden: LLM unreachable — sk-live-raw-payload",
        variant: "error",
      },
    })
    await bridge.showToast({
      body: {
        message: "🔒 Redacted 7 secret(s) in read output (sk-live-raw-payload)",
        variant: "warning",
      },
    })
    await settle()

    expect(fake.emitted).toEqual([
      { event: WARDEN_NOTIFICATION_EVENT, data: { version: 1, kind: "blocked" } },
      { event: WARDEN_NOTIFICATION_EVENT, data: { version: 1, kind: "withheld" } },
      { event: WARDEN_NOTIFICATION_EVENT, data: { version: 1, kind: "redacted", count: 7 } },
    ])
    expect(JSON.stringify(fake.emitted)).not.toContain("sk-live-raw-payload")
    expect(JSON.stringify(fake.emitted)).not.toContain("/home/user/.env")
  })

  test("registration, emission, and disposal failures never reject", async () => {
    const failedRegistration = createWardenNotificationBridge({
      rpc: fakeRpc({ failRegister: true }).rpc as never,
    })
    await settle()
    expect(failedRegistration.ready).toBe(false)
    await expect(failedRegistration.notify({ kind: "blocked" })).resolves.toBeUndefined()
    await expect(failedRegistration.dispose()).resolves.toBeUndefined()

    const failures: string[] = []
    const failedEmit = fakeRpc({ failEmit: true })
    const bridge = createWardenNotificationBridge({
      rpc: failedEmit.rpc as never,
      onFailure: (message) => failures.push(message),
    })
    await settle()
    await expect(bridge.notify({ kind: "denied" })).resolves.toBeUndefined()
    await expect(bridge.dispose()).resolves.toBeUndefined()
    expect(failures).toContain("Warden notification delivery failed")
  })

  test("legacy classifier retains only a closed class", () => {
    expect(notificationFromLegacyToast({ body: { message: "🛡 Denied: policy" } }))
      .toEqual({ kind: "denied" })
    expect(notificationFromLegacyToast({ body: { message: "⚠️ Risk detected (high)" } }))
      .toEqual({ kind: "risk" })
    expect(notificationFromLegacyToast({ body: { message: "Config: something" } }))
      .toEqual({ kind: "warning" })
    expect(notificationFromLegacyToast({ body: { message: "" } })).toBeNull()
  })
})

describe("TUI notification companion", () => {
  function fakeTui(options: { throwToast?: boolean } = {}) {
    let handler: ((event: { data: unknown }) => void) | null = null
    let disposed = 0
    let subscribedDefinition: unknown
    let subscribedEvent: string | undefined
    const toasts: Array<{ title?: string; message: string; variant?: string }> = []
    const attention: Array<{ title?: string; message: string }> = []

    const context = {
      client: {
        rpc(definition: unknown) {
          subscribedDefinition = definition
          return {
            events: {
              on(event: string, callback: (event: { data: unknown }) => void) {
                subscribedEvent = event
                handler = callback
                return () => {
                  disposed += 1
                }
              },
            },
          }
        },
      },
      ui: {
        toast: {
          show(toast: { title?: string; message: string; variant?: string }) {
            if (options.throwToast) throw new Error("renderer gone")
            toasts.push(toast)
          },
        },
      },
      attention: {
        async notify(input: { title?: string; message: string }) {
          attention.push(input)
          return { ok: true, notification: true, sound: false }
        },
      },
    }

    return {
      context: context as unknown as Parameters<typeof registerWardenTuiNotifications>[0],
      fire(data: unknown) {
        if (!handler) throw new Error("not subscribed")
        handler({ data })
      },
      toasts,
      attention,
      get disposed() {
        return disposed
      },
      get subscribedDefinition() {
        return subscribedDefinition
      },
      get subscribedEvent() {
        return subscribedEvent
      },
    }
  }

  test("subscribes to the public contract and renders fixed copy", async () => {
    const fake = fakeTui()
    const registration = registerWardenTuiNotifications(fake.context)

    expect(fake.subscribedDefinition).toBe(WardenNotificationDefinition)
    expect(fake.subscribedEvent).toBe(WARDEN_NOTIFICATION_EVENT)

    fake.fire({ version: 1, kind: "blocked", tool: "shell" })
    await Promise.resolve()

    expect(fake.toasts).toEqual([
      {
        title: "Warden",
        message: "🛡 Warden blocked a tool call (shell)",
        variant: "error",
      },
    ])
    expect(fake.attention).toHaveLength(1)

    registration.dispose()
    expect(fake.disposed).toBe(1)
  })

  test("ignores malformed data and never renders extra raw fields", async () => {
    const fake = fakeTui()
    registerWardenTuiNotifications(fake.context)

    fake.fire({ version: 2, kind: "blocked" })
    fake.fire({ version: 1, kind: "not-a-kind", message: "secret" })
    fake.fire({
      version: 1,
      kind: "redacted",
      tool: "bad\u001b[31mtool",
      count: 2,
      message: "sk-live-raw-payload",
    })
    await Promise.resolve()

    expect(fake.toasts).toHaveLength(1)
    expect(fake.toasts[0]?.message).toBe("🔒 Warden redacted 2 secrets")
    expect(JSON.stringify(fake.toasts)).not.toContain("sk-live-raw-payload")
    expect(JSON.stringify(fake.toasts)).not.toContain("\u001b")
  })

  test("toast failures do not escape and critical events still notify", async () => {
    const fake = fakeTui({ throwToast: true })
    registerWardenTuiNotifications(fake.context)

    expect(() => fake.fire({ version: 1, kind: "denied" })).not.toThrow()
    await Promise.resolve()
    expect(fake.attention).toHaveLength(1)

    expect(() => fake.fire({ version: 1, kind: "warning" })).not.toThrow()
    await Promise.resolve()
    expect(fake.attention).toHaveLength(1)
  })

  test("copy remains fixed for every kind", () => {
    for (const [kind, variant] of [
      ["blocked", "error"],
      ["denied", "error"],
      ["withheld", "error"],
      ["redacted", "warning"],
      ["risk", "warning"],
      ["warning", "warning"],
    ] as const) {
      const toast = toastForWardenNotification({ version: 1, kind })
      expect(toast.variant).toBe(variant)
      expect(toast.message.length).toBeGreaterThan(0)
      expect(toast.message).not.toContain("undefined")
    }
  })
})

describe("Packaging", () => {
  test("publishes the existing entry plus TUI and RPC entrypoints", () => {
    const pkg = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as {
      main: string
      exports: Record<string, { import: string; types: string }>
      scripts: Record<string, string>
    }

    expect(pkg.main).toBe("dist/index.js")
    expect(pkg.exports["."]?.import).toBe("./dist/index.js")
    expect(pkg.exports["./rpc"]?.import).toBe("./dist/rpc.js")
    expect(pkg.exports["./tui"]?.import).toBe("./dist/tui.js")

    const build = pkg.scripts.build
    expect(build).toContain("src/index.ts")
    expect(build).toContain("src/rpc.ts")
    expect(build).toContain("src/tui.ts")
  })

  test("declares the 2.0.18 SDK API floor while developing against 2.1.4", () => {
    const pkg = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as {
      peerDependencies: Record<string, string>
      devDependencies: Record<string, string>
    }

    // Peer range = consumer API floor (verified against the published 2.0.18
    // SDK types). The dev dependency stays on 2.1.4 for type-checking; the
    // typed Tool.Error veto mapping is a 2.0.29+ host behavior, not a peer API.
    expect(pkg.peerDependencies["@opencode/plugin"]).toBe("^2.0.18")
    expect(pkg.devDependencies["@opencode/plugin"]).toBe("^2.1.4")
  })
})
