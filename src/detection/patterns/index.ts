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
): DetectionPattern[] {
  const disabledSet = new Set(disabledPatterns)

  // Filter built-in patterns by category and disabled list
  const patterns = ALL_BUILTIN_PATTERNS.filter(
    (p) => enabledCategories[p.category] && !disabledSet.has(p.id),
  )

  // Add custom patterns
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
      })
    } catch {
      warnings?.push(
        `Invalid custom pattern "${custom.id}": ${custom.pattern}`,
      )
    }
  }

  return patterns
}

export function getAllBuiltinPatterns(): DetectionPattern[] {
  return [...ALL_BUILTIN_PATTERNS]
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
