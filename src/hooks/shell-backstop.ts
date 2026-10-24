import { isAbsolute, resolve } from "path"
import type { AuditLogger } from "../audit/index.js"
import type { DiagnosticLogger } from "../audit/diagnostic-logger.js"
import type { SecurityGuardConfig } from "../types.js"
import {
  extractFileTargets,
  extractRemoteFilePathsFromArgs,
  isDynamicPathTarget,
  isPathBlockedForMode,
} from "../utils/paths.js"

// ─────────────────────────────────────────────────────────────────────────────
// Global shell creation backstop (V2 `shell.create.before`).
//
// Runs on every shell spawn, not only agent tool calls. It is deliberately
// deterministic (no LLM) and has no session identity: the shell event carries
// no sessionID, and inventing one from env/filenames would be spoofable. Audit
// entries therefore use an empty session/call id.
//
// CWD RESOLUTION: OpenCode runs this hook before the shell tool resolves its
// workdir. If the event cwd is relative, resolve it against the plugin's
// location directory (the same root the shell tool uses), then apply the
// existing read/write path protections against that absolute cwd.
//
// USER SHELL EFFECT: because this hook is process-wide, a configured blocked
// path also prevents the user's own terminals/background shells from reading or
// writing that path. That is intentional for the blocklist, but it is broader
// than agent enforcement; document it for users. Dynamic shell targets (e.g.
// `$VAR`, backticks) cannot be verified deterministically and are skipped here
// because the agent-facing input sanitizer already fails closed on them.
// ─────────────────────────────────────────────────────────────────────────────

export interface ShellCreateEventLike {
  command: string
  cwd?: string
}

interface ShellBackstopDeps {
  config: SecurityGuardConfig
  projectDir: string
  auditLogger: AuditLogger
  diagnosticLogger: DiagnosticLogger | null
}

/**
 * Resolve the absolute cwd used for path matching. OpenCode's shell tool
 * defaults to the location directory and resolves relative workdirs against
 * that location before spawn; mirror that here without requiring a session.
 */
export function resolveShellCwd(projectDir: string, cwd: unknown): string {
  if (typeof cwd === "string" && cwd.trim().length > 0) {
    return isAbsolute(cwd) ? resolve(cwd) : resolve(projectDir, cwd)
  }
  return resolve(projectDir)
}

export function createShellBackstop(deps: ShellBackstopDeps) {
  const { config, projectDir, auditLogger, diagnosticLogger } = deps

  return async (event: ShellCreateEventLike): Promise<void> => {
    const command = typeof event.command === "string" ? event.command : ""
    if (command.length === 0) return

    const cwd = resolveShellCwd(projectDir, event.cwd)
    const targets = extractFileTargets("shell", { command })

    for (const target of targets) {
      if (isDynamicPathTarget(target.path)) {
        // Agent-originated commands are already blocked by the input sanitizer;
        // user shells cannot be resolved without executing the shell.
        diagnosticLogger?.decision(
          "shell-backstop",
          "shell",
          `Skipped dynamic ${target.mode} target: ${target.path}`,
        )
        continue
      }

      if (
        !isPathBlockedForMode(
          target.path,
          target.mode,
          config.blockedFilePaths,
          config.writeProtectedPaths,
          config.whitelistedPaths,
          cwd,
        )
      ) {
        continue
      }

      const blockReason = `Blocked file path (${target.mode}): ${target.path}`
      diagnosticLogger?.decision("shell-backstop", "shell", blockReason)

      try {
        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: "shell",
          hook: "shell",
          sessionId: "",
          callId: "",
          detections: [],
          blocked: true,
          blockReason,
          redactedCount: 0,
        })
      } catch {
        // Audit failure is non-critical; the block still applies.
      }

      throw new Error(
        `Security Guard: shell ${target.mode} of "${target.path}" is blocked by ` +
          `the global shell backstop. This path is on the sensitive-file blocklist ` +
          `or write-protection list.`,
      )
    }

    for (const remote of extractRemoteFilePathsFromArgs("shell", { command })) {
      if (
        !isPathBlockedForMode(
          remote.path,
          remote.mode,
          config.blockedFilePaths,
          config.writeProtectedPaths,
          config.whitelistedPaths,
        )
      ) {
        continue
      }

      const blockReason = `Blocked remote file path (${remote.mode}): ${remote.path}`
      diagnosticLogger?.decision("shell-backstop", "shell", blockReason)

      try {
        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: "shell",
          hook: "shell",
          sessionId: "",
          callId: "",
          detections: [],
          blocked: true,
          blockReason,
          redactedCount: 0,
        })
      } catch {
        // Audit failure is non-critical; the block still applies.
      }

      throw new Error(
        `Security Guard: remote shell ${remote.mode} of "${remote.path}" is blocked ` +
          `by the global shell backstop.`,
      )
    }
  }
}
