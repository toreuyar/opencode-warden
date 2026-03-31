import { readFileSync, existsSync } from "fs"
import type { AuditEntry } from "../types.js"

export interface AuditQueryOptions {
  tool?: string
  eventType?: "block" | "detection" | "pass" | "safety-block" | "safety-warn"
  category?: string
  timeStart?: string
  timeEnd?: string
  limit?: number
}

/**
 * Read and filter audit log entries from JSONL files.
 * Reads current log + rotated files (newest first), stops at limit.
 */
export function readAuditEntries(
  filePath: string,
  maxFiles: number,
  options: AuditQueryOptions = {},
): AuditEntry[] {
  const limit = options.limit ?? 20
  const results: AuditEntry[] = []

  // Build file list: current first, then rotated (newest to oldest)
  const files: string[] = []
  if (existsSync(filePath)) files.push(filePath)
  for (let i = 1; i <= maxFiles; i++) {
    const rotated = `${filePath}.${i}`
    if (existsSync(rotated)) files.push(rotated)
  }

  for (const file of files) {
    if (results.length >= limit) break

    let content: string
    try {
      content = readFileSync(file, "utf-8")
    } catch {
      continue
    }

    const lines = content.split("\n").filter((l) => l.trim().length > 0)

    // Parse newest-first within each file (lines are appended chronologically)
    for (let i = lines.length - 1; i >= 0; i--) {
      if (results.length >= limit) break

      let entry: AuditEntry
      try {
        entry = JSON.parse(lines[i]) as AuditEntry
      } catch {
        continue // skip malformed lines
      }

      if (matchesFilter(entry, options)) {
        results.push(entry)
      }
    }
  }

  return results
}

function matchesFilter(entry: AuditEntry, options: AuditQueryOptions): boolean {
  if (options.tool && entry.tool !== options.tool) return false

  if (options.eventType) {
    switch (options.eventType) {
      case "block":
        if (!entry.blocked) return false
        break
      case "detection":
        if (entry.detections.length === 0 && !entry.llmDetections) return false
        break
      case "pass":
        if (entry.blocked || entry.detections.length > 0) return false
        break
      case "safety-block":
        if (entry.safetyEvaluation?.recommendation !== "block") return false
        break
      case "safety-warn":
        if (entry.safetyEvaluation?.recommendation !== "warn") return false
        break
    }
  }

  if (options.category) {
    const hasCategory = entry.detections.some((d) => d.category === options.category)
    if (!hasCategory) return false
  }

  if (options.timeStart && entry.timestamp < options.timeStart) return false
  if (options.timeEnd && entry.timestamp > options.timeEnd) return false

  return true
}
