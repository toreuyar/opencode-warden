import type { DetectionEngine } from "../detection/engine.js"
import type { DetectionMatch } from "../types.js"

interface DeepScanResult {
  value: unknown
  totalMatches: number
  allMatches: DetectionMatch[]
}

const MAX_DEPTH = 10

/**
 * Recursively walk an object/array, scan all string values through the detection engine,
 * and return a redacted deep copy with match counts.
 */
export function deepScan(
  value: unknown,
  engine: DetectionEngine,
  depth: number = 0,
): DeepScanResult {
  if (depth > MAX_DEPTH) {
    return { value, totalMatches: 0, allMatches: [] }
  }

  if (typeof value === "string") {
    const result = engine.scan(value)
    return {
      value: result.redacted,
      totalMatches: result.matches.length,
      allMatches: result.matches,
    }
  }

  if (Array.isArray(value)) {
    let totalMatches = 0
    const allMatches: DetectionMatch[] = []
    const arr = value.map((item) => {
      const scanned = deepScan(item, engine, depth + 1)
      totalMatches += scanned.totalMatches
      allMatches.push(...scanned.allMatches)
      return scanned.value
    })
    return { value: arr, totalMatches, allMatches }
  }

  if (value !== null && typeof value === "object") {
    let totalMatches = 0
    const allMatches: DetectionMatch[] = []
    const obj: Record<string, unknown> = {}

    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      const scanned = deepScan(val, engine, depth + 1)
      obj[key] = scanned.value
      totalMatches += scanned.totalMatches
      allMatches.push(...scanned.allMatches)
    }

    return { value: obj, totalMatches, allMatches }
  }

  // Primitives (number, boolean, null, undefined) pass through
  return { value, totalMatches: 0, allMatches: [] }
}
