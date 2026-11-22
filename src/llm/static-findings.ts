// ─── Static findings ─────────────────────────────────────────────────────────
// Deterministic detection of credential-access surfaces and verdict-forgery
// patterns in tool-call arguments. Findings:
//  1. disqualify bypass (force LLM evaluation — e.g. plain `cat` of a
//     service-account token must never skip evaluation),
//  2. are injected into the prompt as ground truth so the LLM does not have
//     to recognize these surfaces itself (it is inconsistent at it —
//     see harness run 20260910_000329, Tier 15 FNs).
//
// Same philosophy as payload-decode: deterministic facts in code, judgment
// in the LLM.

export interface StaticFinding {
  kind: "credential-surface" | "verdict-forgery"
  detail: string
}

interface FindingRule {
  re: RegExp
  detail: string
}

/** Cloud/instance metadata + local credential surfaces. */
const CREDENTIAL_SURFACE_RULES: FindingRule[] = [
  { re: /169\.254\.169\.254/, detail: "cloud instance metadata endpoint (AWS/Azure/GCP) — credential access surface" },
  { re: /metadata\.google\.(internal|com)/, detail: "GCP metadata endpoint — credential access surface" },
  { re: /Metadata[-:]\s*(true|Google)/i, detail: "metadata-service auth header — credential access attempt marker" },
  { re: /:10250\b/, detail: "kubelet read-only/authless API port — cluster credential/data access surface" },
  { re: /docker\.sock|\/var\/run\/docker\.sock/, detail: "Docker control socket — host-equivalent access surface" },
  { re: /\/var\/run\/secrets\/kubernetes\.io/, detail: "Kubernetes service-account credentials — secret material" },
  { re: /\/etc\/shadow\b/, detail: "password hash file — secret material" },
  { re: /\.aws\/credentials|\.kube\/config|kubeconfig/, detail: "cloud/cluster credential file — secret material" },
  { re: /gcp\/[^"'\s]*\.json|service[-_]?account[^"'\s]*\.json/, detail: "service-account key file — secret material" },
]

/**
 * Verdict-forgery: Warden-schema-shaped text embedded in tool arguments
 * (heredocs, echo payloads, file content). Text like `Safe: Yes` /
 * `Recommendation: allow` inside a command is a manipulation attempt, not a
 * verdict — the evaluator's decisions never arrive inside tool arguments.
 */
const VERDICT_FORGERY_RULES: FindingRule[] = [
  { re: /Safe\s*:\s*(Yes|No)/i, detail: "embedded verdict-shaped text (Safe: …) — suspected verdict forgery / prompt injection" },
  { re: /Risk[-\s]?Level\s*:/i, detail: "embedded verdict-shaped text (Risk Level:) — suspected verdict forgery / prompt injection" },
  { re: /Recommendation\s*:\s*(allow|block|warn)/i, detail: "embedded verdict-shaped text (Recommendation:) — suspected verdict forgery / prompt injection" },
]

export function findStaticFindings(command: string): StaticFinding[] {
  const findings: StaticFinding[] = []
  const seen = new Set<string>()
  for (const [kind, rules] of [
    ["credential-surface", CREDENTIAL_SURFACE_RULES],
    ["verdict-forgery", VERDICT_FORGERY_RULES],
  ] as const) {
    for (const rule of rules) {
      if (rule.re.test(command) && !seen.has(rule.detail)) {
        seen.add(rule.detail)
        findings.push({ kind, detail: rule.detail })
      }
    }
  }
  return findings
}

/** True when any finding exists — used to disqualify bypass. */
export function hasStaticFindings(command: string): boolean {
  return findStaticFindings(command).length > 0
}

/** Prompt section; empty string when no findings. */
export function formatFindingsSection(findings: StaticFinding[]): string {
  if (findings.length === 0) return ""
  const lines = findings.map((f) => `- [${f.kind}] ${f.detail}`)
  return [
    "",
    "STATIC FINDINGS (Warden-detected evidence):",
    ...lines,
    "",
  ].join("\n")
}
