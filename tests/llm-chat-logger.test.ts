import { describe, test, expect, afterEach } from "bun:test"
import { LlmChatLogger } from "../src/audit/llm-chat-logger.js"
import { existsSync, readFileSync, rmSync } from "fs"
import { join } from "path"

const TMP_DIR = join(process.cwd(), ".test-tmp-chat-logger")
const LOG_PATH = join(TMP_DIR, "llm-chat.log")

function cleanup() {
  if (existsSync(TMP_DIR)) {
    rmSync(TMP_DIR, { recursive: true, force: true })
  }
}

afterEach(cleanup)

function makeConfig() {
  return {
    filePath: LOG_PATH,
    maxFileSize: 10 * 1024 * 1024,
    maxFiles: 3,
  }
}

describe("LlmChatLogger", () => {
  test("creates directory on construction", () => {
    cleanup()
    const _logger = new LlmChatLogger(makeConfig())
    expect(existsSync(TMP_DIR)).toBe(true)
  })

  test("startCall writes header and messages", () => {
    const logger = new LlmChatLogger(makeConfig())
    logger.startCall("safety-evaluator", "bash", [
      { role: "system", content: "You are a security evaluator." },
      { role: "user", content: "Evaluate: rm -rf /" },
    ])
    expect(existsSync(LOG_PATH)).toBe(true)
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("safety-evaluator")
    expect(content).toContain("bash")
    expect(content).toContain("SYSTEM")
    expect(content).toContain("You are a security evaluator.")
    expect(content).toContain("USER")
    expect(content).toContain("Evaluate: rm -rf /")
    expect(content).toContain("ASSISTANT")
  })

  test("startCall includes provider name when provided", () => {
    const logger = new LlmChatLogger(makeConfig())
    logger.startCall("output-sanitizer", "read", [
      { role: "system", content: "test" },
    ], "ollama-local")
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("ollama-local")
  })

  test("writeChunk appends content tokens", () => {
    const logger = new LlmChatLogger(makeConfig())
    logger.startCall("test", "bash", [{ role: "system", content: "sys" }])
    logger.writeChunk('{"safe": true')
    logger.writeChunk(', "riskLevel": "low"}')
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain('{"safe": true')
    expect(content).toContain('"riskLevel": "low"}')
  })

  test("writeThinkingChunk wraps in thinking markers", () => {
    const logger = new LlmChatLogger(makeConfig())
    logger.startCall("test", "bash", [{ role: "system", content: "sys" }])
    logger.writeThinkingChunk("let me think about this...")
    logger.writeThinkingChunk("the command looks safe")
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("⟨thinking⟩")
    expect(content).toContain("let me think about this...")
    expect(content).toContain("the command looks safe")
  })

  test("switching from thinking to content closes thinking block", () => {
    const logger = new LlmChatLogger(makeConfig())
    logger.startCall("test", "bash", [{ role: "system", content: "sys" }])
    logger.writeThinkingChunk("thinking...")
    logger.writeChunk('{"safe": true}')
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("⟨thinking⟩")
    expect(content).toContain("⟩") // closing marker
    expect(content).toContain('{"safe": true}')
  })

  test("endCall writes timing footer", () => {
    const logger = new LlmChatLogger(makeConfig())
    logger.startCall("test", "bash", [{ role: "system", content: "sys" }])
    logger.writeChunk("token1")
    logger.writeChunk("token2")
    logger.endCall(150)
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("150ms")
    expect(content).toContain("◼")
  })

  test("endCall includes token stats", () => {
    const logger = new LlmChatLogger(makeConfig())
    logger.startCall("test", "bash", [{ role: "system", content: "sys" }])
    logger.writeChunk("a")
    logger.writeChunk("b")
    logger.writeChunk("c")
    logger.endCall(100)
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("3 tok")
    expect(content).toContain("tok/s")
  })

  test("endCall closes thinking block if still open", () => {
    const logger = new LlmChatLogger(makeConfig())
    logger.startCall("test", "bash", [{ role: "system", content: "sys" }])
    logger.writeThinkingChunk("still thinking...")
    logger.endCall(50)
    const content = readFileSync(LOG_PATH, "utf-8")
    expect(content).toContain("⟩") // thinking closed
    expect(content).toContain("50ms")
  })

  test("rotates files when maxFileSize exceeded", () => {
    const logger = new LlmChatLogger({
      ...makeConfig(),
      maxFileSize: 100, // very small
    })
    logger.startCall("test", "bash", [{ role: "system", content: "A".repeat(200) }])
    // First call creates a large file, second should trigger rotation
    logger.startCall("test", "bash", [{ role: "system", content: "B".repeat(200) }])
    expect(existsSync(`${LOG_PATH}.1`)).toBe(true)
  })
})
