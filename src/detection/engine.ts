import type {
  DetectionPattern,
  DetectionMatch,
  ScanResult,
} from "../types.js"

export class DetectionEngine {
  private patterns: DetectionPattern[]

  constructor(patterns: DetectionPattern[]) {
    this.patterns = patterns
  }

  /**
   * Scan input text for all matching patterns and return redacted version.
   */
  scan(input: string): ScanResult {
    if (!input || input.length === 0) {
      return { redacted: input, matches: [], hasDetections: false }
    }

    const allMatches: DetectionMatch[] = []

    for (const pattern of this.patterns) {
      // Reset regex lastIndex for global patterns
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags)

      let match: RegExpExecArray | null
      while ((match = regex.exec(input)) !== null) {
        const original = match[0]
        const redacted = pattern.redact(original)

        // Skip if redaction didn't change anything (e.g., non-sensitive IP)
        if (redacted === original) continue

        allMatches.push({
          patternId: pattern.id,
          patternName: pattern.name,
          category: pattern.category,
          confidence: pattern.confidence,
          original,
          redacted,
          startIndex: match.index,
          endIndex: match.index + original.length,
        })
      }
    }

    if (allMatches.length === 0) {
      return { redacted: input, matches: [], hasDetections: false }
    }

    // Resolve overlapping matches: keep the longer match
    const resolved = resolveOverlaps(allMatches)

    // Sort by startIndex descending to apply replacements from end to start
    resolved.sort((a, b) => b.startIndex - a.startIndex)

    // Apply redactions
    let redacted = input
    for (const m of resolved) {
      redacted =
        redacted.substring(0, m.startIndex) +
        m.redacted +
        redacted.substring(m.endIndex)
    }

    // Re-sort for output (ascending by position)
    resolved.sort((a, b) => a.startIndex - b.startIndex)

    return {
      redacted,
      matches: resolved,
      hasDetections: true,
    }
  }

  /**
   * Quick boolean check for sensitive data (short-circuits on first match).
   */
  hasSensitiveData(input: string): boolean {
    if (!input || input.length === 0) return false

    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags)
      const match = regex.exec(input)
      if (match) {
        const redacted = pattern.redact(match[0])
        if (redacted !== match[0]) return true
      }
    }
    return false
  }

  /**
   * Replace the pattern set (used when custom patterns are added/removed at runtime).
   */
  setPatterns(patterns: DetectionPattern[]): void {
    this.patterns = patterns
  }

  /**
   * Get current pattern list.
   */
  getPatterns(): DetectionPattern[] {
    return [...this.patterns]
  }
}

const CONFIDENCE_ORDER: Record<string, number> = {
  high: 3,
  medium: 2,
  low: 1,
}

/**
 * Resolve overlapping matches by keeping the longer match.
 * For same-length overlaps, prefer higher confidence.
 */
function resolveOverlaps(matches: DetectionMatch[]): DetectionMatch[] {
  if (matches.length <= 1) return matches

  // Sort by startIndex, then by length descending, then by confidence descending
  const sorted = [...matches].sort((a, b) => {
    if (a.startIndex !== b.startIndex) return a.startIndex - b.startIndex
    const aLen = a.endIndex - a.startIndex
    const bLen = b.endIndex - b.startIndex
    if (aLen !== bLen) return bLen - aLen
    return (CONFIDENCE_ORDER[b.confidence] || 0) - (CONFIDENCE_ORDER[a.confidence] || 0)
  })

  const result: DetectionMatch[] = [sorted[0]]

  for (let i = 1; i < sorted.length; i++) {
    const current = sorted[i]
    const last = result[result.length - 1]

    // If current overlaps with last, keep the better one
    if (current.startIndex < last.endIndex) {
      const currentLen = current.endIndex - current.startIndex
      const lastLen = last.endIndex - last.startIndex
      if (currentLen > lastLen) {
        result[result.length - 1] = current
      } else if (
        currentLen === lastLen &&
        (CONFIDENCE_ORDER[current.confidence] || 0) >
          (CONFIDENCE_ORDER[last.confidence] || 0)
      ) {
        result[result.length - 1] = current
      }
    } else {
      result.push(current)
    }
  }

  return result
}
