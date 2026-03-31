import type { DetectionPattern, PatternCategory, CustomPatternConfig } from "../../types.js"
import { apiKeyPatterns } from "./api-keys.js"
import { credentialPatterns } from "./credentials.js"
import { privateKeyPatterns } from "./private-keys.js"
import { dockerPatterns } from "./docker.js"
import { kubernetesPatterns } from "./kubernetes.js"
import { cloudPatterns } from "./cloud.js"
import { piiPatterns } from "./pii.js"

const ALL_BUILTIN_PATTERNS: DetectionPattern[] = [
  ...apiKeyPatterns,
  ...credentialPatterns,
  ...privateKeyPatterns,
  ...dockerPatterns,
  ...kubernetesPatterns,
  ...cloudPatterns,
  ...piiPatterns,
]

export function getPatterns(
  enabledCategories: Record<PatternCategory, boolean>,
  disabledPatterns: string[],
  customPatterns: CustomPatternConfig[],
  warnings?: string[],
  aiPatterns?: DetectionPattern[],
): DetectionPattern[] {
  const disabledSet = new Set(disabledPatterns)

  // Layer 1: Built-in patterns (immutable, cannot be altered at runtime)
  const patterns: DetectionPattern[] = ALL_BUILTIN_PATTERNS
    .filter((p) => enabledCategories[p.category] && !disabledSet.has(p.id))
    .map((p) => ({ ...p, source: "builtin" as const }))

  // Layer 2: User-defined patterns from config files (immutable at runtime)
  for (const custom of customPatterns) {
    if (!enabledCategories[custom.category]) continue
    if (disabledSet.has(custom.id)) continue

    try {
      const regex = new RegExp(custom.pattern, "g")
      patterns.push({
        id: custom.id,
        name: custom.name,
        category: custom.category,
        pattern: regex,
        redact: () => custom.redactTemplate,
        confidence: custom.confidence,
        source: "user",
      })
    } catch {
      warnings?.push(
        `Invalid custom pattern "${custom.id}": ${custom.pattern}`,
      )
    }
  }

  // Layer 3: AI-managed patterns (added/removed at runtime, session-only)
  if (aiPatterns) {
    for (const p of aiPatterns) {
      if (!enabledCategories[p.category]) continue
      patterns.push(p)
    }
  }

  return patterns
}

export function getAllBuiltinPatterns(): DetectionPattern[] {
  return ALL_BUILTIN_PATTERNS.map((p) => ({ ...p, source: "builtin" as const }))
}

export {
  apiKeyPatterns,
  credentialPatterns,
  privateKeyPatterns,
  dockerPatterns,
  kubernetesPatterns,
  cloudPatterns,
  piiPatterns,
}
