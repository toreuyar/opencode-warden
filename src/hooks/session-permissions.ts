import { isAbsolute, relative, resolve } from "path"
import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type { PermissionRule, SecurityGuardConfig } from "../types.js"
import { isPathBlockedForMode } from "../utils/paths.js"
import { canonicalToolName, toolNameAliases } from "../utils/tool-compat.js"

// ─────────────────────────────────────────────────────────────────────────────
// Session-scoped deny-rule sync (defense-in-depth)
//
// OpenCode merges permission rulesets with `Permission.merge()` (a flat concat)
// and resolves the LAST matching rule, so a session rule appended after the
// agent ruleset can narrow it. `session.update({ permissions })` REPLACES the
// session ruleset, so this module always re-reads the current ruleset and
// appends Warden's rules instead of writing them from scratch.
//
// CONCURRENCY: the host API has no compare-and-set. A concurrent host write
// between the final read and the update can be overwritten (last writer wins).
// A second read before writing detects the common race and defers, but this is
// a best-effort check, not atomicity. Warden must never claim otherwise; the
// synchronous `session.permissions` invalidation lets a later sync re-merge
// host changes.
//
// This is NOT the primary enforcement layer. `tool.execute.before`,
// `permission.evaluate`, the shell backstop, and output redaction remain
// authoritative. A failed read, update, or unsupported runtime shape is
// therefore non-authoritative and must never broaden access.
//
// Translation policy:
//  - `blockedTools` entries are literal tool names. They translate exactly to
//    deny rules for every accepted alias spelling (shell/bash, subagent/task).
//    Entries containing permission wildcards are omitted: Warden's blockedTools
//    comparison is literal, so translating them with permission glob semantics
//    would broaden the deny.
//  - Path policies translate only when the configured entry is a literal
//    absolute path (no `*` / `?`, no `~`, no `host:` prefix). Warden's glob
//    matcher (`*` excludes `/`) is not equivalent to OpenCode's permission
//    wildcard (`*` matches everything), so glob entries are omitted. Relative
//    literals are omitted because Warden suffix-matches them while a permission
//    resource is an exact string.
//  - For in-project paths, both the absolute path and the host's project-
//    relative resource are emitted. The host uses relative resources for
//    in-project files and absolute resources outside the project; emitting only
//    one form would make the session rule inert.
//  - Read/write semantics are preserved through the action names:
//    blockedFilePaths denies read actions and write actions; writeProtectedPaths
//    denies only write actions. A path that Warden allowlists is not emitted at
//    all.
//  - Shell/resource path policy is not representable (a shell permission
//    resource is the raw command string) and is omitted.
// ─────────────────────────────────────────────────────────────────────────────

const READ_FILE_ACTIONS = ["read", "glob", "grep"] as const
const WRITE_FILE_ACTIONS = ["write", "edit", "patch"] as const

/** Entries with permission wildcard syntax cannot be translated literally. */
const WILDCARD_ENTRY = /[*?]/

function addRule(
  rules: PermissionRule[],
  seen: Set<string>,
  action: string,
  resource: string,
): void {
  const key = `${action}\u0000${resource}`
  if (seen.has(key)) return
  seen.add(key)
  rules.push({ action, resource, effect: "deny" })
}

/**
 * Return a literal absolute path that is safe to translate 1:1, or null when
 * the entry uses glob/expansion syntax Warden does not share with OpenCode.
 */
function literalAbsolutePath(entry: string): string | null {
  const trimmed = entry.trim()
  if (trimmed.length === 0) return null
  if (trimmed.startsWith("~") || trimmed.startsWith("host:")) return null
  if (!isAbsolute(trimmed)) return null
  if (WILDCARD_ENTRY.test(trimmed)) return null
  // Normalize exactly like the host does (`path.resolve`) so the rule refers to
  // the same lexical target. Both matchers also normalize backslashes.
  return resolve(trimmed).replace(/\\/g, "/")
}

/**
 * Host permission resources are project-relative for files inside the location
 * directory (`path.relative(location.directory, absolute) || "."`) and absolute
 * for files outside it. Emit both representations for in-project paths so the
 * deny rule actually matches the host's resource without broadening it to
 * unrelated relative resources.
 */
function projectRelativeResource(absolutePath: string, projectDir?: string): string | null {
  if (!projectDir) return null
  const rel = relative(resolve(projectDir), absolutePath).replace(/\\/g, "/")
  if (rel.length === 0 || rel === "." || rel === "..") return null
  if (rel.startsWith("../") || isAbsolute(rel)) return null
  return rel
}

/**
 * Build the deterministic subset of Warden policy that OpenCode session
 * permission rules can express without broadening a deny or changing
 * read/write/whitelist semantics.
 */
export function buildSessionDenyRules(
  config: SecurityGuardConfig,
  projectDir?: string,
): PermissionRule[] {
  const rules: PermissionRule[] = []
  const seen = new Set<string>()

  for (const entry of config.blockedTools) {
    const trimmed = entry.trim()
    if (trimmed.length === 0 || WILDCARD_ENTRY.test(trimmed)) continue
    const canonical = canonicalToolName(trimmed)
    if (canonical === "*") continue
    for (const alias of toolNameAliases(canonical)) {
      addRule(rules, seen, alias, "*")
    }
  }

  const addPathRules = (entry: string): void => {
    const path = literalAbsolutePath(entry)
    if (!path) return

    const resources = [path]
    const relativePath = projectRelativeResource(path, projectDir)
    if (relativePath !== null) resources.push(relativePath)

    const addForMode = (actions: readonly string[], mode: "read" | "write"): void => {
      if (
        !isPathBlockedForMode(
          path,
          mode,
          config.blockedFilePaths,
          config.writeProtectedPaths,
          config.whitelistedPaths,
          projectDir,
        )
      ) {
        return
      }
      for (const action of actions) {
        for (const resource of resources) addRule(rules, seen, action, resource)
      }
    }

    addForMode(READ_FILE_ACTIONS, "read")
    addForMode(WRITE_FILE_ACTIONS, "write")
  }

  for (const entry of config.blockedFilePaths) addPathRules(entry)
  for (const entry of config.writeProtectedPaths) addPathRules(entry)

  return rules
}

function ruleKey(rule: PermissionRule): string {
  return `${rule.action}\u0000${rule.resource}\u0000${rule.effect}`
}

function rulesFingerprint(rules: ReadonlyArray<PermissionRule>): string {
  return rules.map((rule) => ruleKey(rule)).join("\n")
}

/**
 * Preserve the host's current session rules in order, then append Warden deny
 * rules that are not already present. Invalid/foreign entries are preserved
 * only when they match the structural rule shape; the host owns validation.
 */
export function mergePermissionRules(
  existing: ReadonlyArray<PermissionRule> | null | undefined,
  wardenRules: ReadonlyArray<PermissionRule>,
): PermissionRule[] {
  const merged: PermissionRule[] = []
  const seen = new Set<string>()

  for (const rule of existing ?? []) {
    if (
      !rule ||
      typeof rule.action !== "string" ||
      typeof rule.resource !== "string" ||
      (rule.effect !== "allow" && rule.effect !== "deny" && rule.effect !== "ask")
    ) {
      continue
    }
    const copy: PermissionRule = {
      action: rule.action,
      resource: rule.resource,
      effect: rule.effect,
    }
    const key = ruleKey(copy)
    if (seen.has(key)) continue
    seen.add(key)
    merged.push(copy)
  }

  for (const rule of wardenRules) {
    const key = ruleKey(rule)
    if (seen.has(key)) continue
    seen.add(key)
    merged.push({ ...rule })
  }

  return merged
}

export interface SessionPermissionSyncDeps {
  config: SecurityGuardConfig
  projectDir?: string
  diagnosticLogger: DiagnosticLogger | null
  /**
   * Read the current session ruleset. Called once to merge and, when an update
   * is necessary, a second time immediately before writing. Return `null` when
   * the session cannot be read (missing/unsupported runtime): no update is
   * attempted.
   */
  getSessionPermissions: (
    sessionID: string,
  ) => Promise<ReadonlyArray<PermissionRule> | null>
  /** Replace the session ruleset exactly as provided (host semantics). */
  updateSessionPermissions: (
    sessionID: string,
    permissions: ReadonlyArray<PermissionRule>,
  ) => Promise<void>
  debugLog?: (message: string) => void
}

export interface SessionPermissionSync {
  /**
   * Synchronize one session's narrowing rules. Concurrent calls share the same
   * in-flight promise. Failures resolve `false`, are logged as non-authoritative,
   * and allow a later retry.
   */
  sync: (sessionID: string) => Promise<boolean>
  /** Drop cached/in-flight state for a deleted session (race-safe). */
  forget: (sessionID: string) => void
  /** Rules this instance would add (exposed for diagnostics/tests). */
  rules: ReadonlyArray<PermissionRule>
}

/**
 * Create a per-session sync coordinator.
 *
 * The map stores the in-flight/settled promise itself. `forget()` deletes it;
 * a late failure only deletes the entry when it still belongs to the same
 * promise, so a re-created session's newer sync cannot be evicted by an older
 * one.
 */
export function createSessionPermissionSync(
  deps: SessionPermissionSyncDeps,
): SessionPermissionSync {
  const denyRules = buildSessionDenyRules(deps.config, deps.projectDir)
  const syncs = new Map<string, Promise<boolean>>()

  const sync = (sessionID: string): Promise<boolean> => {
    if (!sessionID) return Promise.resolve(false)
    if (denyRules.length === 0) return Promise.resolve(true)

    const inFlight = syncs.get(sessionID)
    if (inFlight) return inFlight

    const promise = (async (): Promise<boolean> => {
      try {
        const current = await deps.getSessionPermissions(sessionID)
        if (current === null) {
          deps.debugLog?.(
            `Session permission sync: could not read session ${sessionID}; primary guards remain authoritative`,
          )
          return false
        }

        const merged = mergePermissionRules(current, denyRules)
        const added = merged.length - current.length
        if (added > 0) {
          // The host API has no compare-and-set. Re-read immediately before
          // writing and abandon this attempt if the host changed the ruleset in
          // the meantime. This narrows the race window but is NOT atomic: a
          // concurrent write after this check can still be overwritten. Warden
          // never describes this sync as atomic; the primary guards remain
          // authoritative and the next `session.permissions` invalidation
          // re-merges host changes.
          const latest = await deps.getSessionPermissions(sessionID)
          if (latest === null) return false
          if (rulesFingerprint(latest) !== rulesFingerprint(current)) {
            deps.debugLog?.(
              `Session permission sync: concurrent host change for ${sessionID}; deferring update`,
            )
            return false
          }

          await deps.updateSessionPermissions(sessionID, merged)
          deps.diagnosticLogger?.info(
            `Session permission sync: added ${added} deny rule(s) for ${sessionID}`,
          )
          deps.debugLog?.(
            `Session permission sync: session ${sessionID} now has ${merged.length} rule(s) (${added} added)`,
          )
        }
        return true
      } catch {
        // Defense-in-depth only: never turn a sync failure into an allow/deny
        // decision. The primary guards still run on the actual call.
        deps.diagnosticLogger?.decision(
          "session-permissions",
          "session.update",
          "Session permission sync failed; primary guards remain authoritative",
        )
        deps.debugLog?.(
          `Session permission sync failed for ${sessionID}; primary guards remain authoritative`,
        )
        return false
      }
    })()

    syncs.set(sessionID, promise)
    void promise.then((ok) => {
      if (!ok && syncs.get(sessionID) === promise) syncs.delete(sessionID)
    })
    return promise
  }

  const forget = (sessionID: string): void => {
    if (!sessionID) return
    syncs.delete(sessionID)
  }

  return { sync, forget, rules: denyRules }
}
