import { existsSync, mkdirSync, statSync, renameSync, appendFileSync } from "fs"
import { dirname } from "path"
import type { DiagnosticLogConfig } from "../types.js"

const THICK_LINE = "═".repeat(63)
const THIN_LINE = "─".repeat(63)

export class DiagnosticLogger {
  private readonly filePath: string
  private readonly maxFileSize: number
  private readonly maxFiles: number
  private seq = 0

  constructor(config: DiagnosticLogConfig) {
    this.filePath = config.filePath
    this.maxFileSize = config.maxFileSize
    this.maxFiles = config.maxFiles

    const dir = dirname(this.filePath)
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true })
    }
  }

  hookStart(
    hook: string,
    tool: string,
    callId: string,
    sessionId: string,
    data?: Record<string, unknown>,
  ): void {
    const lines: string[] = [
      THICK_LINE,
      `[${this.ts()}] #${++this.seq} HOOK-START  ${hook}`,
      THIN_LINE,
      `tool: ${tool} | callId: ${callId} | session: ${sessionId}`,
    ]
    if (data) {
      lines.push(JSON.stringify(data, null, 2))
    }
    lines.push(THICK_LINE)
    this.emit(lines)
  }

  hookEnd(
    hook: string,
    tool: string,
    callId: string,
    durationMs: number,
    data?: Record<string, unknown>,
  ): void {
    const lines: string[] = [
      THICK_LINE,
      `[${this.ts()}] #${++this.seq} HOOK-END  ${hook}`,
      THIN_LINE,
      `tool: ${tool} | callId: ${callId} | duration: ${durationMs}ms`,
    ]
    if (data) {
      lines.push(JSON.stringify(data, null, 2))
    }
    lines.push(THICK_LINE)
    this.emit(lines)
  }

  step(hook: string, message: string, data?: Record<string, unknown>): void {
    const lines: string[] = [
      THIN_LINE,
      `[${this.ts()}] #${++this.seq} STEP  ${hook}`,
      `  ${message}`,
    ]
    if (data) {
      lines.push(JSON.stringify(data, null, 2))
    }
    lines.push(THIN_LINE)
    this.emit(lines)
  }

  decision(
    hook: string,
    tool: string,
    message: string,
    data?: Record<string, unknown>,
  ): void {
    const lines: string[] = [
      THIN_LINE,
      `[${this.ts()}] #${++this.seq} DECISION  ${hook}`,
      `  tool: ${tool} | ${message}`,
    ]
    if (data) {
      lines.push(JSON.stringify(data, null, 2))
    }
    lines.push(THIN_LINE)
    this.emit(lines)
  }

  info(message: string, data?: Record<string, unknown>): void {
    const lines: string[] = [
      THICK_LINE,
      `[${this.ts()}] #${++this.seq} INFO`,
      `  ${message}`,
    ]
    if (data) {
      lines.push(JSON.stringify(data, null, 2))
    }
    lines.push(THICK_LINE)
    this.emit(lines)
  }

  startup(message: string, data?: Record<string, unknown>): void {
    const lines: string[] = [
      THICK_LINE,
      `[${this.ts()}] #${++this.seq} STARTUP`,
      `  ${message}`,
    ]
    if (data) {
      lines.push(JSON.stringify(data, null, 2))
    }
    lines.push(THICK_LINE)
    this.emit(lines)
  }

  private ts(): string {
    return new Date().toISOString()
  }

  private emit(lines: string[]): void {
    const block = lines.join("\n") + "\n\n"
    try {
      this.rotateIfNeeded()
      appendFileSync(this.filePath, block, "utf-8")
    } catch {
      // Diagnostic logging must never break the plugin
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
