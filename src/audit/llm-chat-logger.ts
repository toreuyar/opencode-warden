import { existsSync, mkdirSync, statSync, renameSync, appendFileSync } from "fs"
import { dirname } from "path"
import type { LlmMessage } from "../types.js"

const THICK_LINE = "═".repeat(63)

export interface LlmChatLoggerConfig {
  filePath: string
  maxFileSize: number
  maxFiles: number
}

export class LlmChatLogger {
  private readonly filePath: string
  private readonly maxFileSize: number
  private readonly maxFiles: number
  private inThinking = false

  // Per-call streaming stats
  private callStartMs = 0
  private firstTokenMs = 0
  private tokenCount = 0

  constructor(config: LlmChatLoggerConfig) {
    this.filePath = config.filePath
    this.maxFileSize = config.maxFileSize
    this.maxFiles = config.maxFiles

    const dir = dirname(this.filePath)
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true })
    }
  }

  /**
   * Write the header and all system/user messages for a new LLM call.
   * Optional providerName shows which provider in the chain is being used.
   */
  startCall(component: string, tool: string, messages: LlmMessage[], providerName?: string): void {
    this.inThinking = false
    this.callStartMs = Date.now()
    this.firstTokenMs = 0
    this.tokenCount = 0
    this.rotateIfNeeded()

    const headerParts = [component, tool]
    if (providerName) headerParts.push(providerName)

    const lines: string[] = [
      THICK_LINE,
      `[${this.ts()}] ${headerParts.join(" | ")}`,
      THICK_LINE,
      "",
    ]

    for (const msg of messages) {
      const label = msg.role.toUpperCase()
      lines.push(`▶ ${label}`)
      lines.push(msg.content)
      lines.push("")
    }

    lines.push("▶ ASSISTANT")
    this.write(lines.join("\n") + "\n")
  }

  /**
   * Append a content token from the streaming response.
   * Written immediately for real-time tail -f visibility.
   */
  writeChunk(text: string): void {
    // If we were in thinking mode, close the thinking block first
    if (this.inThinking) {
      this.write("⟩\n")
      this.inThinking = false
    }
    this.trackToken()
    this.write(text)
  }

  /**
   * Append a thinking/reasoning token from the streaming response.
   * Wrapped in ⟨thinking⟩...⟩ markers.
   */
  writeThinkingChunk(text: string): void {
    if (!this.inThinking) {
      this.write("⟨thinking⟩\n")
      this.inThinking = true
    }
    this.trackToken()
    this.write(text)
  }

  /**
   * Write the timing footer and separator after the LLM call completes.
   */
  endCall(durationMs: number): void {
    if (this.inThinking) {
      this.write("⟩\n")
      this.inThinking = false
    }

    const parts: string[] = [`${durationMs}ms`, `[${this.ts()}]`]

    if (this.tokenCount > 0) {
      parts.push(`${this.tokenCount} tok`)

      // tg: tokens per second (generation phase only, excluding TTFT)
      const ttft = this.firstTokenMs > 0 ? this.firstTokenMs - this.callStartMs : 0
      const genMs = durationMs - ttft
      if (genMs > 0) {
        const tokPerSec = (this.tokenCount / genMs) * 1000
        parts.push(`${tokPerSec.toFixed(1)} tok/s`)
      }

      // ttft: time to first token
      if (ttft > 0) {
        parts.push(`ttft ${ttft}ms`)
      }
    }

    this.write(`\n\n◼ ${parts.join(" | ")}\n${THICK_LINE}\n\n`)
  }

  private trackToken(): void {
    if (!this.firstTokenMs) {
      this.firstTokenMs = Date.now()
    }
    this.tokenCount++
  }

  private ts(): string {
    return new Date().toISOString()
  }

  private write(text: string): void {
    try {
      appendFileSync(this.filePath, text, "utf-8")
    } catch {
      // Chat logging must never break the plugin
    }
  }

  private rotateIfNeeded(): void {
    if (!existsSync(this.filePath)) return

    try {
      const stat = statSync(this.filePath)
      if (stat.size < this.maxFileSize) return

      for (let i = this.maxFiles - 1; i >= 1; i--) {
        const from = `${this.filePath}.${i}`
        const to = `${this.filePath}.${i + 1}`
        if (existsSync(from) && i + 1 <= this.maxFiles) {
          renameSync(from, to)
        }
      }
      renameSync(this.filePath, `${this.filePath}.1`)
    } catch {
      // Rotation failure is non-critical
    }
  }
}
