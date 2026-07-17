import { existsSync, realpathSync } from "fs"
import { dirname, isAbsolute, join, normalize, resolve } from "path"
import { parseSshCommand, extractRemoteFilePaths } from "./ssh.js"

const RSYNC_REMOTE_PATH_RE = /^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*:(.+)$/

const RCLONE_REMOTE_PATH_RE = /^[A-Za-z][A-Za-z0-9_-]*:(.+)$/

function extractRsyncRemotePaths(command: string): { path: string; mode: "read" | "write" }[] {
  const out: { path: string; mode: "read" | "write" }[] = []
  const tokens = tokenizeCommand(command)

  if (tokens.length === 0 || tokens[0] !== "rsync") return []

  // Collect non-flag operands. `-e` consumes the next token (the rsh command).
  const operands: string[] = []
  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i]
    if (tok === "-e") {
      i++ // skip rsh argument
      continue
    }
    if (tok.startsWith("-")) continue
    operands.push(tok)
  }
  if (operands.length === 0) return out

  // Last operand is the destination; earlier operands are sources.
  const lastIdx = operands.length - 1
  for (let k = 0; k < operands.length; k++) {
    const match = RSYNC_REMOTE_PATH_RE.exec(operands[k])
    if (match) {
      out.push({ path: match[1], mode: k === lastIdx ? "write" : "read" })
    }
  }

  return out
}

function extractRcloneRemotePaths(command: string): { path: string; mode: "read" | "write" }[] {
  const out: { path: string; mode: "read" | "write" }[] = []
  const tokens = tokenizeCommand(command)

  if (tokens.length === 0 || tokens[0] !== "rclone") return []

  // rclone subcommands look like: rclone copy src dest
  // Collect operands after the subcommand.
  const operands: string[] = []
  let seenSubcommand = false
  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i]
    if (!seenSubcommand && /^[a-z]+$/.test(tok)) {
      seenSubcommand = true
      continue
    }
    if (tok.startsWith("-")) continue
    operands.push(tok)
  }
  if (operands.length === 0) return out

  // For copy/sync/move: last operand is destination (write), earlier are sources (read).
  // For a single operand (e.g. `rclone ls remote:path`): treat as read.
  const lastIdx = operands.length - 1
  for (let k = 0; k < operands.length; k++) {
    const match = RCLONE_REMOTE_PATH_RE.exec(operands[k])
    if (match) {
      const mode = operands.length >= 2 && k === lastIdx ? "write" : "read"
      out.push({ path: match[1], mode })
    }
  }

  return out
}

function tokenizeCommand(command: string): string[] {
  const tokens: string[] = []
  let current = ""
  let inSingle = false
  let inDouble = false
  let escaped = false

  for (let i = 0; i < command.length; i++) {
    const ch = command[i]

    if (escaped) {
      current += ch
      escaped = false
      continue
    }

    if (ch === "\\" && !inSingle) {
      escaped = true
      continue
    }

    if (ch === "'" && !inDouble) {
      inSingle = !inSingle
      continue
    }

    if (ch === '"' && !inSingle) {
      inDouble = !inDouble
      continue
    }

    if ((ch === " " || ch === "\t") && !inSingle && !inDouble) {
      if (current.length > 0) {
        tokens.push(current)
        current = ""
      }
      continue
    }

    if ((ch === ">" || ch === "<") && !inSingle && !inDouble) {
      let op = ch
      if (command[i + 1] === ch) {
        op += command[i + 1]
        i++
      }

      if (/^(?:\d+|&)$/.test(current)) {
        tokens.push(current + op)
      } else {
        if (current.length > 0) tokens.push(current)
        tokens.push(op)
      }
      current = ""
      continue
    }

    current += ch
  }

  if (current.length > 0) {
    tokens.push(current)
  }

  return tokens
}

/**
 * Check if a path is in the session allowlist. Allowlists are exact path
 * matches only; broad pattern matching belongs in the blocklist.
 */
export function isAllowlisted(filePath: string, allowlist: Set<string>, cwd?: string): boolean {
  const candidates = getPathCandidates(filePath, "read", cwd)
  const allowCandidates = [...allowlist].flatMap((p) => getPathCandidates(p, "read", cwd))
  return candidates.some((candidate) => allowCandidates.includes(candidate))
}

function normalizeForMatch(filePath: string): string {
  return normalize(filePath).replace(/\\/g, "/")
}

function toAbsolutePath(filePath: string, cwd?: string): string {
  if (filePath.startsWith("~/")) {
    const home = process.env.HOME || process.env.USERPROFILE || ""
    if (home) return resolve(home, filePath.slice(2))
  }
  return isAbsolute(filePath)
    ? resolve(filePath)
    : resolve(cwd || process.cwd(), filePath)
}

function nearestExistingParent(filePath: string): string | null {
  let current = dirname(filePath)
  while (current && current !== dirname(current)) {
    if (existsSync(current)) return current
    current = dirname(current)
  }
  return existsSync(current) ? current : null
}

export function getPathCandidates(
  filePath: string,
  mode: "read" | "write",
  cwd?: string,
): string[] {
  const candidates = new Set<string>()
  if (!filePath) return []

  candidates.add(normalizeForMatch(filePath))

  const absolute = toAbsolutePath(filePath, cwd)
  candidates.add(normalizeForMatch(absolute))

  try {
    if (existsSync(absolute)) {
      candidates.add(normalizeForMatch(realpathSync(absolute)))
    } else if (mode === "write") {
      const parent = nearestExistingParent(absolute)
      if (parent) {
        const realParent = realpathSync(parent)
        const relativeRemainder = absolute.slice(parent.length).replace(/^[/\\]+/, "")
        candidates.add(normalizeForMatch(join(realParent, relativeRemainder)))
      }
    }
  } catch {
    // Keep lexical candidates when canonicalization is unavailable.
  }

  return [...candidates]
}

function isExactlyWhitelisted(
  filePath: string,
  whitelistedPatterns: string[],
  mode: "read" | "write",
  cwd?: string,
): boolean {
  const pathCandidates = getPathCandidates(filePath, mode, cwd)
  const whitelistCandidates = whitelistedPatterns.flatMap((p) =>
    getPathCandidates(p, mode, cwd),
  )
  return pathCandidates.some((candidate) => whitelistCandidates.includes(candidate))
}

/**
 * Check if a file path matches any of the blocked patterns.
 * Whitelist takes priority over blocklist.
 */
export function isBlockedPath(
  filePath: string,
  blockedPatterns: string[],
  whitelistedPatterns: string[],
  cwd?: string,
): boolean {
  if (isExactlyWhitelisted(filePath, whitelistedPatterns, "read", cwd)) return false

  // Check blocklist
  for (const candidate of getPathCandidates(filePath, "read", cwd)) {
    for (const pattern of blockedPatterns) {
      if (matchGlob(candidate, pattern)) {
        return true
      }
    }
  }

  return false
}

/**
 * Check if a file path matches any write-protected pattern.
 * Write-protected paths may be READ but not WRITTEN (e.g. logs, state files).
 * Whitelist takes priority — an allowlisted path is never write-protected.
 *
 * Callers check writes with: `isBlockedPath(...) || isWriteProtectedPath(...)`.
 * Read access checks only `isBlockedPath(...)` — write-protection does not
 * restrict reads.
 */
export function isWriteProtectedPath(
  filePath: string,
  writeProtectedPatterns: string[],
  whitelistedPatterns: string[],
  cwd?: string,
): boolean {
  if (isExactlyWhitelisted(filePath, whitelistedPatterns, "write", cwd)) return false

  for (const candidate of getPathCandidates(filePath, "write", cwd)) {
    for (const pattern of writeProtectedPatterns) {
      if (matchGlob(candidate, pattern)) {
        return true
      }
    }
  }

  return false
}

/**
 * Combined check: is this path blocked for the given access mode?
 * - "read": blocked if in blockedFilePaths (secrets).
 * - "write": blocked if in blockedFilePaths OR writeProtectedPaths.
 * Whitelist always wins.
 */
export function isPathBlockedForMode(
  filePath: string,
  mode: "read" | "write",
  blockedPatterns: string[],
  writeProtectedPatterns: string[],
  whitelistedPatterns: string[],
  cwd?: string,
): boolean {
  if (isBlockedPath(filePath, blockedPatterns, whitelistedPatterns, cwd)) return true
  if (mode === "write" && isWriteProtectedPath(filePath, writeProtectedPatterns, whitelistedPatterns, cwd)) {
    return true
  }
  return false
}

/**
 * Simple glob matching supporting *, **, and ? wildcards.
 */
export function matchGlob(path: string, pattern: string): boolean {
  const normalizedPattern = pattern.replace(/\\/g, "/")
  const normalizedPath = path.replace(/\\/g, "/")

  // Convert glob to regex
  let regex = ""
  let i = 0
  while (i < normalizedPattern.length) {
    const char = normalizedPattern[i]

    if (char === "*") {
      if (normalizedPattern[i + 1] === "*") {
        // ** matches any number of directories
        if (normalizedPattern[i + 2] === "/") {
          regex += "(?:.*/)?";
          i += 3
        } else {
          regex += ".*"
          i += 2
        }
      } else {
        // * matches anything except /
        regex += "[^/]*"
        i++
      }
    } else if (char === "?") {
      regex += "[^/]"
      i++
    } else if (char === ".") {
      regex += "\\."
      i++
    } else if (char === "(") {
      regex += "\\("
      i++
    } else if (char === ")") {
      regex += "\\)"
      i++
    } else if (char === "{") {
      regex += "\\{"
      i++
    } else if (char === "}") {
      regex += "\\}"
      i++
    } else if (char === "+") {
      regex += "\\+"
      i++
    } else if (char === "^") {
      regex += "\\^"
      i++
    } else if (char === "$") {
      regex += "\\$"
      i++
    } else if (char === "|") {
      regex += "\\|"
      i++
    } else if (char === "[") {
      regex += "\\["
      i++
    } else if (char === "]") {
      regex += "\\]"
      i++
    } else {
      regex += char
      i++
    }
  }

  // The pattern should match the end of the path (or the full path if it starts with **)
  const fullRegex = normalizedPattern.startsWith("**/")
    ? new RegExp(`(?:^|/)${regex}$`)
    : new RegExp(`(?:^|/)${regex}$`)

  return fullRegex.test(normalizedPath) || new RegExp(`^${regex}$`).test(normalizedPath)
}

/**
 * Extract file path from tool arguments.
 * Different tools put the path in different arg keys.
 */
export function extractFilePath(
  tool: string,
  args: Record<string, unknown>,
): string | undefined {
  switch (tool) {
    case "read":
    case "write":
      return args.filePath as string | undefined
    case "edit":
      return args.filePath as string | undefined
    case "patch":
      return args.filePath as string | undefined
    case "glob":
      return typeof args.path === "string" ? args.path : undefined
    case "bash": {
      // Try to extract file paths from bash commands
      const command = args.command as string | undefined
      if (!command) return undefined

      // Check for SSH identity file path (-i flag)
      const parsed = parseSshCommand(command)
      if (parsed?.identityFile) return parsed.identityFile

      // Look for common file-reading patterns
      const catMatch = command.match(/\bcat\s+['"]?([^\s'"]+)/)
      if (catMatch) return catMatch[1]
      const lessMatch = command.match(/\bless\s+['"]?([^\s'"]+)/)
      if (lessMatch) return lessMatch[1]
      return undefined
    }
    default:
      return undefined
  }
}

/**
 * Extract remote file paths (with access mode) from SSH/SCP/rsync/rclone
 * commands in bash tool args. Returns empty array for non-remote commands.
 *
 * Mode is derived from transfer direction:
 * - SCP/rsync/rclone upload (local→remote): remote destination is a WRITE.
 * - SCP/rsync/rclone download (remote→local): remote source is a READ.
 * - SSH inner-command file references: READS (inner writes are the LLM's job).
 */
export function extractRemoteFilePathsFromArgs(
  tool: string,
  args: Record<string, unknown>,
): { path: string; mode: "read" | "write" }[] {
  if (tool !== "bash") return []

  const command = args.command as string | undefined
  if (!command) return []

  const parsed = parseSshCommand(command)
  if (parsed) {
    return extractRemoteFilePaths(parsed)
  }

  if (command.trimStart().startsWith("rsync")) {
    return extractRsyncRemotePaths(command)
  }

  if (command.trimStart().startsWith("rclone")) {
    return extractRcloneRemotePaths(command)
  }

  return []
}

/**
 * Returns true if a redirection target string is a real file path (not an
 * fd-duplication marker, fd-close, /dev/null, or pure number).
 */
function isRealRedirectTarget(p: string): boolean {
  if (!p) return false
  if (p.startsWith("&")) return false // fd-duplication (&1, &2)
  if (p === "-") return false // fd-close marker
  if (p === "/dev/null") return false
  if (p.startsWith("/dev/fd/")) return false
  if (/^\d+$/.test(p)) return false // pure number, not a path
  return true
}

export function isDynamicPathTarget(p: string): boolean {
  return /(?:^|[^\\])(?:\$[{(]?|`)/.test(p)
}

/**
 * Extract file paths that a bash command reads or writes via shell redirection,
 * `tee`, `truncate`, or `dd of=`. Used to enforce the blockedFilePaths and
 * writeProtectedPaths lists against bash commands — not just read/write/edit
 * tool calls.
 *
 * Without this, an agent could bypass the file blocklist by writing via shell
 * redirection (e.g. `echo '...' >> ~/.ssh/authorized_keys`, `truncate -s 0 /var/log/syslog`).
 *
 * WRITE targets (checked against blockedFilePaths + writeProtectedPaths):
 *  - Output/append redirect:  > file, >> file, 1> file, 2> file, &> file, 1>> file, 2>> file, &>> file
 *  - tee:                     tee file, tee -a file, tee file1 file2 ...
 *  - truncate:                truncate -s 0 file ...
 *  - dd output file:          dd ... of=file
 *
 * READ targets (checked against blockedFilePaths only):
 *  - Input redirect:          < file
 *
   * Skips: fd-duplication (2>&1, <&3), fd-close (>&-), heredocs (<<), /dev/null,
   * and pure-numeric tokens. Quoting and glued redirection operators are handled
   * by the tokenizer.
 */
export function extractBashFileTargets(command: string): {
  reads: string[]
  writes: string[]
} {
  const reads: string[] = []
  const writes: string[] = []
  if (!command) return { reads, writes }

  const tokens = tokenizeCommand(command)

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]

    // Output/append redirect operator as a standalone token: >, >>, 1>, 2>, &>, 1>>, 2>>, &>>
    if (/^(\d+|&)?>>?$/.test(tok)) {
      const next = tokens[i + 1]
      if (next && isRealRedirectTarget(next)) writes.push(next)
      continue
    }

    // Output/append redirect GLUED to target: >file, 2>file, >>file, &>file, &>>file
    const gluedOut = tok.match(/^(?:\d+|&)?>>?(.+)/)
    if (gluedOut) {
      const target = gluedOut[1]
      if (isRealRedirectTarget(target)) writes.push(target)
      continue
    }

    // Input redirect: < file (but NOT << heredoc)
    if (tok === "<") {
      const next = tokens[i + 1]
      if (next && isRealRedirectTarget(next)) reads.push(next)
      continue
    }
    // Glued input redirect: <file (but NOT <<file heredoc)
    const gluedIn = tok.match(/^<(?!<)(.+)/)
    if (gluedIn) {
      const target = gluedIn[1]
      if (isRealRedirectTarget(target)) reads.push(target)
      continue
    }

    // tee <file>... — writes to every non-flag argument until a pipe / separator
    if (tok === "tee") {
      let j = i + 1
      let optsEnded = false
      while (j < tokens.length) {
        const t = tokens[j]
        if (t === "|" || t === ";" || t === "&&" || t === "||") break
        if (!optsEnded && t === "--") {
          optsEnded = true
          j++
          continue
        }
        if (!optsEnded && t.startsWith("-")) {
          j++
          continue
        }
        if (isRealRedirectTarget(t)) writes.push(t)
        j++
      }
      continue
    }

    // truncate [opts] <file>... — every non-flag argument is a write target
    if (tok === "truncate") {
      let j = i + 1
      let optsEnded = false
      while (j < tokens.length) {
        const t = tokens[j]
        if (t === "|" || t === ";" || t === "&&" || t === "||") break
        if (!optsEnded && t === "--") {
          optsEnded = true
          j++
          continue
        }
        if (!optsEnded && t.startsWith("-")) {
          j++
          continue
        }
        if (isRealRedirectTarget(t)) writes.push(t)
        j++
      }
      continue
    }

    // dd of=<file>
    if (tok.startsWith("of=")) {
      const target = tok.slice(3)
      if (isRealRedirectTarget(target)) writes.push(target)
      continue
    }
  }

  return { reads, writes }
}
