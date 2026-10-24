import type { SecurityGuardConfig } from "../types.js"
import { canonicalToolName, isToolInList } from "../utils/tool-compat.js"

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic tool-surface enforcement.
//
// `blockedTools` is enforced twice before a model can use a tool:
//  1. `tool.transform` removes the tool from the registered surface.
//  2. `session.context` removes it from the per-request definitions.
//
// Both paths match aliases (`bash` ↔ `shell`, `task` ↔ `subagent`) and remove
// tools by their actual editor/request ids. `excludedTools` is unrelated: it
// means "skip Warden processing", not "hide the tool".
// ─────────────────────────────────────────────────────────────────────────────

export interface TransformToolLike {
  readonly id: string
  readonly name?: string
}

export interface ToolTransformEditorLike {
  list(): readonly TransformToolLike[]
  remove(id: string): void
}

export interface RequestToolSurface {
  [name: string]: unknown
}

function isBlockedName(name: string, blockedTools: readonly string[]): boolean {
  return isToolInList(name, blockedTools)
}

/**
 * Remove every blocked tool from a transform editor. `editor.remove()` takes
 * the effective id (including a namespace prefix), not the raw tool name, so
 * iterate the live list and match against both the effective id and raw name.
 */
export function removeBlockedTransformTools(
  editor: ToolTransformEditorLike,
  config: SecurityGuardConfig,
): string[] {
  if (config.blockedTools.length === 0) return []

  const removed: string[] = []
  for (const tool of editor.list()) {
    if (typeof tool.id !== "string" || tool.id.length === 0) continue
    const names = [tool.id]
    if (typeof tool.name === "string" && tool.name.length > 0) names.push(tool.name)
    if (!names.some((name) => isBlockedName(name, config.blockedTools))) continue
    editor.remove(tool.id)
    removed.push(tool.id)
  }
  return removed
}

/**
 * Remove blocked tools from a single request's tool definition map. The map is
 * keyed by the names advertised after context hooks, so deleting a key hides
 * the tool without touching surviving definitions or tool identity mapping.
 * Returns the removed keys for diagnostics/tests.
 */
export function removeBlockedRequestTools(
  tools: RequestToolSurface,
  config: SecurityGuardConfig,
): string[] {
  if (config.blockedTools.length === 0) return []

  const removed: string[] = []
  for (const name of Object.keys(tools)) {
    if (!isBlockedName(name, config.blockedTools)) continue
    delete tools[name]
    removed.push(name)
  }
  return removed
}

/**
 * Effective ids in a transform list for a configured tool, alias-aware. Useful
 * for diagnostics without performing a removal.
 */
export function findToolSurfaceIds(
  tools: readonly TransformToolLike[],
  toolName: string,
): string[] {
  const canonical = canonicalToolName(toolName)
  return tools
    .filter((tool) => {
      const names = [tool.id]
      if (typeof tool.name === "string") names.push(tool.name)
      return names.some((name) => canonicalToolName(name) === canonical)
    })
    .map((tool) => tool.id)
}
