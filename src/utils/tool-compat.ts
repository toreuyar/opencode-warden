/**
 * Tool vocabulary compatibility between the V1 and V2 OpenCode tool surfaces.
 *
 * V2 renamed several tools and arguments:
 *   - `bash`    → `shell`
 *   - `task`    → `subagent`
 *   - `filePath` → `path` (read/write/edit)
 *   - patch inputs now arrive as `patchText` instead of `filePath`
 *
 * Warden's policy vocabulary uses the V2 names as canonical. Legacy names are
 * accepted as aliases so existing user configs and V1-shaped callers keep
 * working without rewriting any config file on disk.
 */

/** Legacy tool name → canonical V2 tool name. */
export const TOOL_NAME_ALIASES: Readonly<Record<string, string>> = Object.freeze({
  bash: "shell",
  task: "subagent",
})

/** Canonical tool name → all accepted names (canonical first). */
const TOOL_NAME_EQUIVALENTS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  shell: ["shell", "bash"],
  subagent: ["subagent", "task"],
})

/**
 * Resolve a tool name to its canonical V2 spelling. Unknown/custom tool names
 * are returned unchanged.
 */
export function canonicalToolName(tool: string): string {
  return TOOL_NAME_ALIASES[tool] ?? tool
}

/**
 * Return every accepted spelling for a tool, canonical first. Used by policy
 * checks that need to match either a V2 or legacy configured name.
 */
export function toolNameAliases(tool: string): string[] {
  const canonical = canonicalToolName(tool)
  return [...(TOOL_NAME_EQUIVALENTS[canonical] ?? [canonical])]
}

/**
 * Compare two tool names under canonicalization. `shell` matches `bash`, and
 * `subagent` matches `task`; everything else is an exact match.
 */
export function toolNamesMatch(a: string, b: string): boolean {
  return canonicalToolName(a) === canonicalToolName(b)
}

/**
 * Check whether a runtime tool name appears in a configured policy list,
 * accepting legacy aliases on both sides.
 */
export function isToolInList(tool: string, list: readonly string[]): boolean {
  const canonical = canonicalToolName(tool)
  return list.some((entry) => canonicalToolName(entry) === canonical)
}

/**
 * Normalize a configured tool-name list in memory: canonicalize aliases,
 * trim entries, drop empties, and remove duplicates while preserving order.
 * The input array is not modified.
 */
export function normalizeToolList(list: readonly string[]): string[] {
  const result: string[] = []
  const seen = new Set<string>()

  for (const entry of list) {
    const trimmed = entry.trim()
    if (trimmed.length === 0) continue
    const canonical = canonicalToolName(trimmed)
    if (seen.has(canonical)) continue
    seen.add(canonical)
    result.push(canonical)
  }

  return result
}

/**
 * Extract a file path from V2 (`path`) or legacy V1 (`filePath`) tool args.
 * V2 wins when both keys are present.
 */
export function extractPathArgument(args: Record<string, unknown>): string | undefined {
  if (typeof args.path === "string" && args.path.length > 0) return args.path
  if (typeof args.filePath === "string" && args.filePath.length > 0) return args.filePath
  return undefined
}
