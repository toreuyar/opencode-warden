import { existsSync, mkdirSync, statSync, renameSync, appendFileSync } from "fs"
import { dirname } from "path"
import type { AuditConfig } from "../types.js"

export class FileLogger {
  private buffer: string[] = []
  private flushTimer: ReturnType<typeof setTimeout> | null = null
  private readonly filePath: string
  private readonly maxFileSize: number
  private readonly maxFiles: number
  private readonly flushInterval = 1000 // 1 second
  private readonly flushThreshold = 10 // entries
  private readonly onError?: (msg: string) => void

  constructor(config: AuditConfig, onError?: (msg: string) => void) {
    this.filePath = config.filePath
    this.maxFileSize = config.maxFileSize
    this.maxFiles = config.maxFiles
    this.onError = onError

    // Ensure directory exists
    const dir = dirname(this.filePath)
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true })
    }
  }

  write(entry: string): void {
    this.buffer.push(entry)

    if (this.buffer.length >= this.flushThreshold) {
      this.flush()
    } else if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), this.flushInterval)
    }
  }

  flush(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer)
      this.flushTimer = null
    }

    if (this.buffer.length === 0) return

    const data = this.buffer.join("\n") + "\n"
    this.buffer = []

    try {
      this.rotateIfNeeded()
      appendFileSync(this.filePath, data, "utf-8")
    } catch (err) {
      this.onError?.(
        `Failed to write audit log: ${err instanceof Error ? err.message : err}`,
      )
    }
  }

  private rotateIfNeeded(): void {
    if (!existsSync(this.filePath)) return

    try {
      const stat = statSync(this.filePath)
      if (stat.size < this.maxFileSize) return

      // Rotate files: audit.log.4 → delete, audit.log.3 → .4, etc.
      for (let i = this.maxFiles - 1; i >= 1; i--) {
        const from = `${this.filePath}.${i}`
        const to = `${this.filePath}.${i + 1}`
        if (existsSync(from)) {
          if (i + 1 > this.maxFiles) {
            // Would exceed max, just let it be overwritten
          } else {
            renameSync(from, to)
          }
        }
      }

      // Rename current to .1
      renameSync(this.filePath, `${this.filePath}.1`)
    } catch (err) {
      this.onError?.(
        `Log rotation error: ${err instanceof Error ? err.message : err}`,
      )
    }
  }

  destroy(): void {
    this.flush()
    if (this.flushTimer) {
      clearTimeout(this.flushTimer)
      this.flushTimer = null
    }
  }
}
