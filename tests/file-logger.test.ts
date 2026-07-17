import { describe, test, expect, afterEach } from "bun:test"
import { FileLogger } from "../src/audit/file-logger.js"
import { existsSync, readFileSync, rmSync, mkdirSync, statSync, symlinkSync, writeFileSync } from "fs"
import { join } from "path"

const TMP_DIR = join(process.cwd(), ".test-tmp-file-logger")
const LOG_PATH = join(TMP_DIR, "audit.log")

function cleanup() {
  if (existsSync(TMP_DIR)) {
    rmSync(TMP_DIR, { recursive: true, force: true })
  }
}

afterEach(cleanup)

function makeConfig(overrides: Record<string, unknown> = {}) {
  return {
    enabled: true,
    filePath: LOG_PATH,
    maxFileSize: 10 * 1024 * 1024,
    maxFiles: 3,
    verbosity: "normal" as const,
    ...overrides,
  }
}

describe("FileLogger", () => {
  test("creates directory if it does not exist", () => {
    cleanup()
    expect(existsSync(TMP_DIR)).toBe(false)
    const logger = new FileLogger(makeConfig())
    logger.destroy()
    expect(existsSync(TMP_DIR)).toBe(true)
  })

  test("write buffers entries", () => {
    const logger = new FileLogger(makeConfig())
    logger.write('{"test": 1}')
    // File is created during initialization so permissions can be pinned to 0600.
    expect(readFileSync(LOG_PATH, "utf-8")).toBe("")
    logger.destroy()
  })

  test("flush writes buffered entries to file", () => {
    const logger = new FileLogger(makeConfig())
    logger.write('{"entry": "one"}')
    logger.write('{"entry": "two"}')
    logger.flush()
    expect(existsSync(LOG_PATH)).toBe(true)
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain('"entry": "one"')
    expect(content).toContain('"entry": "two"')
    logger.destroy()
  })

  test("flush is no-op when buffer is empty", () => {
    const logger = new FileLogger(makeConfig())
    logger.flush()
    expect(readFileSync(LOG_PATH, "utf-8")).toBe("")
    logger.destroy()
  })

  test("creates log directory as 0700 and log file as 0600", () => {
    const logger = new FileLogger(makeConfig())
    logger.destroy()

    expect(statSync(TMP_DIR).mode & 0o777).toBe(0o700)
    expect(statSync(LOG_PATH).mode & 0o777).toBe(0o600)
  })

  test("auto-flushes when buffer reaches threshold (10 entries)", () => {
    const logger = new FileLogger(makeConfig())
    for (let i = 0; i < 10; i++) {
      logger.write(`{"entry": ${i}}`)
    }
    // Should have auto-flushed after 10 entries
    expect(existsSync(LOG_PATH)).toBe(true)
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain('"entry": 0')
    expect(content).toContain('"entry": 9')
    logger.destroy()
  })

  test("destroy flushes remaining buffer", () => {
    const logger = new FileLogger(makeConfig())
    logger.write('{"final": true}')
    logger.destroy()
    expect(existsSync(LOG_PATH)).toBe(true)
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain('"final": true')
  })

  test("rotates log files when maxFileSize is exceeded", () => {
    // Create a logger with a tiny maxFileSize
    const logger = new FileLogger(makeConfig({ maxFileSize: 50 }))

    // Write enough to exceed maxFileSize
    logger.write("A".repeat(60))
    logger.flush()

    // File exists and is > 50 bytes
    expect(existsSync(LOG_PATH)).toBe(true)

    // Write more — should trigger rotation
    logger.write("B".repeat(60))
    logger.flush()

    // Original should have been rotated to .1
    expect(existsSync(`${LOG_PATH}.1`)).toBe(true)
    const rotated = readFileSync(`${LOG_PATH}.1`, "utf-8")
    expect(rotated).toContain("A".repeat(60))

    const current = readFileSync(LOG_PATH, "utf-8")
    expect(current).toContain("B".repeat(60))
    logger.destroy()
  })

  test("calls onError callback and refuses symlink log target", () => {
    let errorMsg = ""
    const target = join(TMP_DIR, "target.log")
    const badPath = join(TMP_DIR, "audit.log")
    mkdirSync(TMP_DIR, { recursive: true })
    writeFileSync(target, "")
    symlinkSync(target, badPath)

    const logger = new FileLogger(
      makeConfig({ filePath: badPath }),
      (msg) => { errorMsg = msg },
    )
    logger.write("test")
    logger.flush()

    expect(errorMsg).toContain("Failed to write audit log")
    logger.destroy()
  })
})
