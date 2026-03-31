import { describe, test, expect, afterEach } from "bun:test"
import { FileLogger } from "../src/audit/file-logger.js"
import { existsSync, readFileSync, rmSync, mkdirSync } from "fs"
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
    // File should not exist yet (buffered)
    expect(existsSync(LOG_PATH)).toBe(false)
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
    expect(existsSync(LOG_PATH)).toBe(false)
    logger.destroy()
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

  test("calls onError callback on write failure", () => {
    let errorMsg = ""
    // Create a read-only directory so appendFileSync fails with EACCES
    const readonlyDir = join(TMP_DIR, "readonly")
    mkdirSync(readonlyDir, { recursive: true })
    const { chmodSync } = require("fs")
    chmodSync(readonlyDir, 0o444)
    const badPath = join(readonlyDir, "audit.log")
    const logger = new FileLogger(
      makeConfig({ filePath: badPath }),
      (msg) => { errorMsg = msg },
    )
    logger.write("test")
    logger.flush()
    // Restore permissions so cleanup can remove the directory
    chmodSync(readonlyDir, 0o755)
    expect(errorMsg).toContain("Failed to write audit log")
    logger.destroy()
  })
})
