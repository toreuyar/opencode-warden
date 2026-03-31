import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import { readAuditEntries } from "../src/audit/audit-reader.js"
import { mkdirSync, writeFileSync, rmSync } from "fs"
import { join } from "path"

const TEST_DIR = join(import.meta.dir, ".audit-reader-fixtures")
const LOG_PATH = join(TEST_DIR, "audit.log")

function writeLog(path: string, entries: object[]) {
  writeFileSync(path, entries.map((e) => JSON.stringify(e)).join("\n") + "\n")
}

function makeEntry(overrides: Record<string, unknown> = {}) {
  return {
    timestamp: "2026-03-31T10:00:00.000Z",
    tool: "bash",
    hook: "before",
    sessionId: "s1",
    callId: "c1",
    detections: [],
    blocked: false,
    redactedCount: 0,
    ...overrides,
  }
}

beforeEach(() => {
  mkdirSync(TEST_DIR, { recursive: true })
})

afterEach(() => {
  rmSync(TEST_DIR, { recursive: true, force: true })
})

describe("readAuditEntries", () => {
  test("returns empty when log file does not exist", () => {
    const entries = readAuditEntries("/nonexistent/audit.log", 5, {})
    expect(entries).toEqual([])
  })

  test("parses JSONL entries", () => {
    writeLog(LOG_PATH, [
      makeEntry({ callId: "c1" }),
      makeEntry({ callId: "c2" }),
    ])
    const entries = readAuditEntries(LOG_PATH, 5, {})
    expect(entries.length).toBe(2)
    // Newest first (c2 before c1)
    expect(entries[0].callId).toBe("c2")
    expect(entries[1].callId).toBe("c1")
  })

  test("filters by tool name", () => {
    writeLog(LOG_PATH, [
      makeEntry({ tool: "bash" }),
      makeEntry({ tool: "read" }),
      makeEntry({ tool: "bash" }),
    ])
    const entries = readAuditEntries(LOG_PATH, 5, { tool: "read" })
    expect(entries.length).toBe(1)
    expect(entries[0].tool).toBe("read")
  })

  test("filters by eventType: block", () => {
    writeLog(LOG_PATH, [
      makeEntry({ blocked: true, blockReason: "dangerous" }),
      makeEntry({ blocked: false }),
    ])
    const entries = readAuditEntries(LOG_PATH, 5, { eventType: "block" })
    expect(entries.length).toBe(1)
    expect(entries[0].blocked).toBe(true)
  })

  test("filters by eventType: detection", () => {
    writeLog(LOG_PATH, [
      makeEntry({ detections: [{ patternId: "x", category: "api-keys", confidence: "high" }] }),
      makeEntry({ detections: [] }),
    ])
    const entries = readAuditEntries(LOG_PATH, 5, { eventType: "detection" })
    expect(entries.length).toBe(1)
    expect(entries[0].detections.length).toBe(1)
  })

  test("filters by eventType: pass", () => {
    writeLog(LOG_PATH, [
      makeEntry({ blocked: false, detections: [] }),
      makeEntry({ blocked: true }),
      makeEntry({ detections: [{ patternId: "x", category: "api-keys", confidence: "high" }] }),
    ])
    const entries = readAuditEntries(LOG_PATH, 5, { eventType: "pass" })
    expect(entries.length).toBe(1)
  })

  test("filters by eventType: safety-block", () => {
    writeLog(LOG_PATH, [
      makeEntry({ safetyEvaluation: { safe: false, riskLevel: "high", riskDimensions: [], explanation: "", suggestedAlternative: "", recommendation: "block" } }),
      makeEntry({ safetyEvaluation: { safe: true, riskLevel: "low", riskDimensions: [], explanation: "", suggestedAlternative: "", recommendation: "allow" } }),
    ])
    const entries = readAuditEntries(LOG_PATH, 5, { eventType: "safety-block" })
    expect(entries.length).toBe(1)
  })

  test("filters by category", () => {
    writeLog(LOG_PATH, [
      makeEntry({ detections: [{ patternId: "x", category: "api-keys", confidence: "high" }] }),
      makeEntry({ detections: [{ patternId: "y", category: "credentials", confidence: "high" }] }),
    ])
    const entries = readAuditEntries(LOG_PATH, 5, { category: "credentials" })
    expect(entries.length).toBe(1)
  })

  test("respects limit", () => {
    writeLog(LOG_PATH, Array.from({ length: 50 }, (_, i) => makeEntry({ callId: `c${i}` })))
    const entries = readAuditEntries(LOG_PATH, 5, { limit: 10 })
    expect(entries.length).toBe(10)
  })

  test("skips malformed lines", () => {
    writeFileSync(LOG_PATH, [
      JSON.stringify(makeEntry({ callId: "good" })),
      "not json at all",
      "{broken json",
      JSON.stringify(makeEntry({ callId: "also-good" })),
    ].join("\n") + "\n")
    const entries = readAuditEntries(LOG_PATH, 5, {})
    expect(entries.length).toBe(2)
  })

  test("reads rotated files", () => {
    writeLog(LOG_PATH, [makeEntry({ callId: "current" })])
    writeLog(LOG_PATH + ".1", [makeEntry({ callId: "rotated-1" })])
    writeLog(LOG_PATH + ".2", [makeEntry({ callId: "rotated-2" })])

    const entries = readAuditEntries(LOG_PATH, 5, { limit: 10 })
    expect(entries.length).toBe(3)
    // Current file first
    expect(entries[0].callId).toBe("current")
    expect(entries[1].callId).toBe("rotated-1")
    expect(entries[2].callId).toBe("rotated-2")
  })

  test("filters by time range", () => {
    writeLog(LOG_PATH, [
      makeEntry({ timestamp: "2026-03-31T08:00:00.000Z" }),
      makeEntry({ timestamp: "2026-03-31T10:00:00.000Z" }),
      makeEntry({ timestamp: "2026-03-31T12:00:00.000Z" }),
    ])
    const entries = readAuditEntries(LOG_PATH, 5, {
      timeStart: "2026-03-31T09:00:00.000Z",
      timeEnd: "2026-03-31T11:00:00.000Z",
    })
    expect(entries.length).toBe(1)
    expect(entries[0].timestamp).toBe("2026-03-31T10:00:00.000Z")
  })
})
