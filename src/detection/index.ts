import type { SecurityGuardConfig } from "../types.js"
import { DetectionEngine } from "./engine.js"
import { getPatterns } from "./patterns/index.js"

export function createDetectionEngine(
  config: SecurityGuardConfig,
  warnings?: string[],
): DetectionEngine {
  const patterns = getPatterns(
    config.categories,
    config.disabledPatterns,
    config.customPatterns,
    warnings,
  )
  return new DetectionEngine(patterns)
}

export { DetectionEngine } from "./engine.js"
export { getPatterns, getAllBuiltinPatterns } from "./patterns/index.js"
export { maskWithEnds, maskFull } from "./redactor.js"
