import { describe, test, expect, mock } from "bun:test"
import { AuditLogger } from "../src/audit/index.js"
import type { AuditConfig, AuditEntry } from "../src/types.js"

function makeConfig(overrides: Partial<AuditConfig> = {}): AuditConfig {
  return {
    enabled: true,
    filePath: "/dev/null", // avoid actual file writes in tests
    maxFileSize: 10 * 1024 * 1024,
    maxFiles: 5,
    verbosity: "normal",
    ...overrides,
  }
}

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: new Date().toISOString(),
    tool: "bash",
    hook: "before",
    sessionId: "test-session",
    callId: "call-1",
    detections: [],
    blocked: false,
    redactedCount: 0,
    ...overrides,
  }
}

describe("AuditLogger", () => {
  describe("disabled state", () => {
    test("log does nothing when disabled", async () => {
      const logger = new AuditLogger(makeConfig({ enabled: false }))
      // Should not throw
      await logger.log(makeEntry({ blocked: true }))
    })
  })

  describe("verbosity filtering", () => {
    test("quiet mode only logs blocked or redacted entries", async () => {
      const logSpy = mock(async () => {})
      const client = {
        app: { log: logSpy },
        session: { prompt: async () => {} },
        tui: { showToast: async () => {} },
      }
      const logger = new AuditLogger(makeConfig({ verbosity: "quiet" }), client as any)

      // This entry has no blocks, no redactions — should be skipped
      await logger.log(makeEntry())
      expect(logSpy).not.toHaveBeenCalled()

      // This entry is blocked — should be logged
      await logger.log(makeEntry({ blocked: true, blockReason: "dangerous" }))
      expect(logSpy).toHaveBeenCalled()
    })

    test("normal mode logs blocked, redacted, and safety evaluations", async () => {
      const logSpy = mock(async () => {})
      const client = {
        app: { log: logSpy },
        session: { prompt: async () => {} },
        tui: { showToast: async () => {} },
      }
      const logger = new AuditLogger(makeConfig({ verbosity: "normal" }), client as any)

      // Clean pass — no block, no redactions, no safety eval
      await logger.log(makeEntry())
      expect(logSpy).not.toHaveBeenCalled()

      // With safety evaluation
      await logger.log(makeEntry({
        safetyEvaluation: {
          safe: true,
          riskLevel: "low",
          riskDimensions: [],
          explanation: "safe",
          suggestedAlternative: "",
          recommendation: "allow",
        },
      }))
      expect(logSpy).toHaveBeenCalledTimes(1)
    })

    test("verbose mode logs everything", async () => {
      const logSpy = mock(async () => {})
      const client = {
        app: { log: logSpy },
        session: { prompt: async () => {} },
        tui: { showToast: async () => {} },
      }
      const logger = new AuditLogger(makeConfig({ verbosity: "verbose" }), client as any)

      // Even a clean pass should be logged
      await logger.log(makeEntry())
      expect(logSpy).toHaveBeenCalledTimes(1)
    })
  })

  describe("log formatting", () => {
    test("formats blocked entries", async () => {
      const logSpy = mock(async () => {})
      const client = {
        app: { log: logSpy },
        session: { prompt: async () => {} },
        tui: { showToast: async () => {} },
      }
      const logger = new AuditLogger(makeConfig({ verbosity: "verbose" }), client as any)
      await logger.log(makeEntry({ blocked: true, blockReason: "dangerous command" }))
      const call = logSpy.mock.calls[0][0] as any
      expect(call.body.message).toContain("BLOCKED")
      expect(call.body.message).toContain("dangerous command")
      expect(call.body.level).toBe("warn")
    })

    test("formats redacted entries", async () => {
      const logSpy = mock(async () => {})
      const client = {
        app: { log: logSpy },
        session: { prompt: async () => {} },
        tui: { showToast: async () => {} },
      }
      const logger = new AuditLogger(makeConfig({ verbosity: "verbose" }), client as any)
      await logger.log(makeEntry({
        redactedCount: 3,
        detections: [
          { patternId: "openai-key", category: "api-keys", confidence: "high" },
          { patternId: "aws-key", category: "cloud", confidence: "high" },
        ],
      }))
      const call = logSpy.mock.calls[0][0] as any
      expect(call.body.message).toContain("REDACTED")
      expect(call.body.message).toContain("3 secret(s)")
      expect(call.body.message).toContain("api-keys")
    })

    test("formats safety evaluation entries", async () => {
      const logSpy = mock(async () => {})
      const client = {
        app: { log: logSpy },
        session: { prompt: async () => {} },
        tui: { showToast: async () => {} },
      }
      const logger = new AuditLogger(makeConfig({ verbosity: "verbose" }), client as any)
      await logger.log(makeEntry({
        safetyEvaluation: {
          safe: false,
          riskLevel: "high",
          riskDimensions: ["destructive-operations"],
          explanation: "bulk deletion",
          suggestedAlternative: "delete specific files",
          recommendation: "block",
        },
      }))
      const call = logSpy.mock.calls[0][0] as any
      expect(call.body.message).toContain("SAFETY BLOCK")
      expect(call.body.message).toContain("high")
    })

    test("formats clean pass entries", async () => {
      const logSpy = mock(async () => {})
      const client = {
        app: { log: logSpy },
        session: { prompt: async () => {} },
        tui: { showToast: async () => {} },
      }
      const logger = new AuditLogger(makeConfig({ verbosity: "verbose" }), client as any)
      await logger.log(makeEntry())
      const call = logSpy.mock.calls[0][0] as any
      expect(call.body.message).toContain("PASS")
      expect(call.body.level).toBe("debug")
    })
  })

  describe("flush / destroy", () => {
    test("flush and destroy do not throw when no file logger", () => {
      const logger = new AuditLogger(makeConfig({ enabled: false }))
      expect(() => logger.flush()).not.toThrow()
      expect(() => logger.destroy()).not.toThrow()
    })
  })
})
