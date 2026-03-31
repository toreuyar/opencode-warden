import { describe, test, expect, afterEach } from "bun:test"
import { DiagnosticLogger } from "../src/audit/diagnostic-logger.js"
import { existsSync, readFileSync, rmSync } from "fs"
import { join } from "path"

const TMP_DIR = join(process.cwd(), ".test-tmp-diag-logger")
const LOG_PATH = join(TMP_DIR, "diagnostic.log")

function cleanup() {
  if (existsSync(TMP_DIR)) {
    rmSync(TMP_DIR, { recursive: true, force: true })
  }
}

afterEach(cleanup)

function makeConfig() {
  return {
    enabled: true,
    filePath: LOG_PATH,
    maxFileSize: 10 * 1024 * 1024,
    maxFiles: 3,
  }
}

describe("DiagnosticLogger", () => {
  test("creates directory on construction", () => {
    cleanup()
    const _logger = new DiagnosticLogger(makeConfig())
    expect(existsSync(TMP_DIR)).toBe(true)
  })

  test("hookStart writes formatted block", () => {
    const logger = new DiagnosticLogger(makeConfig())
    logger.hookStart("input-sanitizer", "bash", "call-1", "session-1", { title: "test cmd" })
    expect(existsSync(LOG_PATH)).toBe(true)
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("HOOK-START")
    expect(content).toContain("input-sanitizer")
    expect(content).toContain("bash")
    expect(content).toContain("call-1")
    expect(content).toContain("session-1")
    expect(content).toContain("test cmd")
  })

  test("hookEnd writes formatted block with duration", () => {
    const logger = new DiagnosticLogger(makeConfig())
    logger.hookEnd("input-sanitizer", "bash", "call-1", 42, { outcome: "allow" })
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("HOOK-END")
    expect(content).toContain("42ms")
    expect(content).toContain("allow")
  })

  test("step writes formatted block", () => {
    const logger = new DiagnosticLogger(makeConfig())
    logger.step("output-redactor", "checking regex patterns", { patternCount: 15 })
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("STEP")
    expect(content).toContain("output-redactor")
    expect(content).toContain("checking regex patterns")
    expect(content).toContain("15")
  })

  test("decision writes formatted block", () => {
    const logger = new DiagnosticLogger(makeConfig())
    logger.decision("safety-evaluator", "bash", "BLOCK: high risk", { riskLevel: "high" })
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("DECISION")
    expect(content).toContain("safety-evaluator")
    expect(content).toContain("BLOCK: high risk")
  })

  test("info writes formatted block", () => {
    const logger = new DiagnosticLogger(makeConfig())
    logger.info("Plugin initialized", { version: "1.0" })
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("INFO")
    expect(content).toContain("Plugin initialized")
  })

  test("startup writes formatted block", () => {
    const logger = new DiagnosticLogger(makeConfig())
    logger.startup("Security guard starting", { categories: 10 })
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("STARTUP")
    expect(content).toContain("Security guard starting")
  })

  test("sequence numbers increment", () => {
    const logger = new DiagnosticLogger(makeConfig())
    logger.info("first")
    logger.info("second")
    logger.info("third")
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("#1")
    expect(content).toContain("#2")
    expect(content).toContain("#3")
  })

  test("handles missing data parameter gracefully", () => {
    const logger = new DiagnosticLogger(makeConfig())
    logger.hookStart("test-hook", "test-tool", "call-1", "session-1")
    logger.hookEnd("test-hook", "test-tool", "call-1", 10)
    logger.step("test-hook", "a step")
    logger.decision("test-hook", "test-tool", "allow")
    logger.info("no data")
    logger.startup("no data startup")
    expect(existsSync(LOG_PATH)).toBe(true)
  })

  test("rotates files when maxFileSize exceeded", () => {
    const logger = new DiagnosticLogger({
      ...makeConfig(),
      maxFileSize: 100, // very small
    })
    // Write enough to exceed maxFileSize
    logger.info("A".repeat(200))
    // Now write more to trigger rotation
    logger.info("B".repeat(200))
    expect(existsSync(`${LOG_PATH}.1`)).toBe(true)
  })
})
