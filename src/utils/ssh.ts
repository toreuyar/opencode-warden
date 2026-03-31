import type { ParsedSshCommand, SshCommandType } from "../types.js"

/**
 * Regex to match user@host or just host in SSH-style commands.
 * Captures: (user)@(host) or just (host).
 */
const USER_HOST_RE = /^(?:([A-Za-z0-9._-]+)@)?([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*)$/

/**
 * Strip leading env var assignments (e.g., `VAR=val VAR2=val2 ssh ...`).
 * Also strip leading pipe-to-SSH patterns (e.g., `cat file | ssh ...`).
 */
function stripPrefix(command: string): string {
  let cmd = command.trimStart()

  // Strip pipe-to-SSH: `something | ssh ...` → `ssh ...`
  const pipeIdx = cmd.search(/\|\s*(ssh|scp|sftp)\b/)
  if (pipeIdx !== -1) {
    cmd = cmd.substring(pipeIdx + 1).trimStart()
  }

  // Strip env var prefixes: `VAR=val ssh ...` → `ssh ...`
  while (/^[A-Za-z_][A-Za-z0-9_]*=\S+\s/.test(cmd)) {
    cmd = cmd.replace(/^[A-Za-z_][A-Za-z0-9_]*=\S+\s+/, "")
  }

  return cmd
}

/**
 * Tokenize a command string, respecting single and double quotes.
 */
function tokenize(command: string): string[] {
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

    current += ch
  }

  if (current.length > 0) {
    tokens.push(current)
  }

  return tokens
}

/**
 * Parse an SSH command string into structured data.
 * Returns null if the command is not an SSH/SCP/SFTP command.
 */
export function parseSshCommand(command: string): ParsedSshCommand | null {
  const stripped = stripPrefix(command)
  const tokens = tokenize(stripped)

  if (tokens.length === 0) return null

  const binary = tokens[0]
  if (binary !== "ssh" && binary !== "scp" && binary !== "sftp") return null

  const type: SshCommandType = binary as SshCommandType

  if (type === "scp") return parseScpCommand(tokens, command)
  if (type === "sftp") return parseSftpCommand(tokens, command)
  return parseSshCommandTokens(tokens, command)
}

function parseSshCommandTokens(
  tokens: string[],
  rawCommand: string,
): ParsedSshCommand | null {
  let port: number | undefined
  let identityFile: string | undefined
  const options: string[] = []
  let host = ""
  let user: string | undefined
  let innerCommand: string | undefined

  let i = 1
  // Parse flags
  while (i < tokens.length) {
    const tok = tokens[i]

    if (tok === "-p" && i + 1 < tokens.length) {
      port = parseInt(tokens[i + 1], 10)
      i += 2
      continue
    }

    if (tok === "-i" && i + 1 < tokens.length) {
      identityFile = tokens[i + 1]
      i += 2
      continue
    }

    if (tok === "-o" && i + 1 < tokens.length) {
      options.push(tokens[i + 1])
      i += 2
      continue
    }

    // Skip other flags that take a value
    if (/^-[bcDEeFIJLlmOoRSWw]$/.test(tok) && i + 1 < tokens.length) {
      i += 2
      continue
    }

    // Skip boolean flags
    if (/^-[46AaCfGgKkMNnqsTtVvXxYy]+$/.test(tok)) {
      i++
      continue
    }

    // Not a flag — this is the host or user@host
    break
  }

  if (i >= tokens.length) return null

  const hostToken = tokens[i]
  const hostMatch = USER_HOST_RE.exec(hostToken)
  if (!hostMatch) return null

  user = hostMatch[1] || undefined
  host = hostMatch[2]
  i++

  // Everything after user@host is the inner command
  if (i < tokens.length) {
    innerCommand = tokens.slice(i).join(" ")
  }

  return {
    type: "ssh",
    rawCommand,
    user,
    host,
    port,
    innerCommand,
    options: options.length > 0 ? options : undefined,
    identityFile,
  }
}

function parseScpCommand(
  tokens: string[],
  rawCommand: string,
): ParsedSshCommand | null {
  let port: number | undefined
  let identityFile: string | undefined
  const options: string[] = []

  let i = 1
  // Parse flags
  while (i < tokens.length) {
    const tok = tokens[i]

    if (tok === "-P" && i + 1 < tokens.length) {
      port = parseInt(tokens[i + 1], 10)
      i += 2
      continue
    }

    if (tok === "-i" && i + 1 < tokens.length) {
      identityFile = tokens[i + 1]
      i += 2
      continue
    }

    if (tok === "-o" && i + 1 < tokens.length) {
      options.push(tokens[i + 1])
      i += 2
      continue
    }

    // Skip other flags that take a value
    if (/^-[cFJlOS]$/.test(tok) && i + 1 < tokens.length) {
      i += 2
      continue
    }

    // Skip boolean flags (e.g., -r, -v, -C, -q, -3, -B, -p, -T)
    if (/^-[rCqBpTv346]+$/.test(tok)) {
      i++
      continue
    }

    // Not a flag — remaining tokens are sources + destination
    break
  }

  // Need at least 2 remaining tokens: source(s) and destination
  const pathTokens = tokens.slice(i)
  if (pathTokens.length < 2) return null

  const sources = pathTokens.slice(0, -1)
  const destination = pathTokens[pathTokens.length - 1]

  // Determine direction and extract host from remote path (user@host:path or host:path)
  const remoteColonRe = /^(?:([A-Za-z0-9._-]+)@)?([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*):(.*)$/

  let host = ""
  let user: string | undefined
  let scpDirection: "upload" | "download" | undefined
  const scpSources: string[] = sources
  const scpDestination: string = destination

  // Check if destination is remote
  const destMatch = remoteColonRe.exec(destination)
  if (destMatch) {
    user = destMatch[1] || undefined
    host = destMatch[2]
    scpDirection = "upload"
  } else {
    // Check if any source is remote
    for (const src of sources) {
      const srcMatch = remoteColonRe.exec(src)
      if (srcMatch) {
        user = srcMatch[1] || undefined
        host = srcMatch[2]
        scpDirection = "download"
        break
      }
    }
  }

  if (!host) return null

  return {
    type: "scp",
    rawCommand,
    user,
    host,
    port,
    scpSources,
    scpDestination,
    scpDirection,
    options: options.length > 0 ? options : undefined,
    identityFile,
  }
}

function parseSftpCommand(
  tokens: string[],
  rawCommand: string,
): ParsedSshCommand | null {
  let port: number | undefined
  let identityFile: string | undefined
  const options: string[] = []

  let i = 1
  while (i < tokens.length) {
    const tok = tokens[i]

    if (tok === "-P" && i + 1 < tokens.length) {
      port = parseInt(tokens[i + 1], 10)
      i += 2
      continue
    }

    if (tok === "-i" && i + 1 < tokens.length) {
      identityFile = tokens[i + 1]
      i += 2
      continue
    }

    if (tok === "-o" && i + 1 < tokens.length) {
      options.push(tokens[i + 1])
      i += 2
      continue
    }

    // Skip other flags that take a value
    if (/^-[bDFJlRS]$/.test(tok) && i + 1 < tokens.length) {
      i += 2
      continue
    }

    // Skip boolean flags
    if (/^-[aCfNpqrv46]+$/.test(tok)) {
      i++
      continue
    }

    break
  }

  if (i >= tokens.length) return null

  const hostToken = tokens[i]
  const hostMatch = USER_HOST_RE.exec(hostToken)
  if (!hostMatch) return null

  return {
    type: "sftp",
    rawCommand,
    user: hostMatch[1] || undefined,
    host: hostMatch[2],
    port,
    options: options.length > 0 ? options : undefined,
    identityFile,
  }
}

/**
 * Extract the inner command from a parsed SSH command.
 * Returns undefined for SCP/SFTP (no inner command concept).
 */
export function extractInnerCommand(
  parsed: ParsedSshCommand,
): string | undefined {
  if (parsed.type !== "ssh") return undefined
  return parsed.innerCommand
}

/**
 * Extract remote file paths referenced in the command.
 * - SSH: parses inner command for cat, less, head, tail targets.
 * - SCP: extracts path from host:path notation.
 */
export function extractRemoteFilePaths(parsed: ParsedSshCommand): string[] {
  const paths: string[] = []

  if (parsed.type === "ssh" && parsed.innerCommand) {
    // Extract file paths from common read commands in inner command
    const readCmdRe =
      /\b(?:cat|less|head|tail|more|vi|vim|nano|view)\s+['"]?([^\s'";&|>]+)/g
    let match: RegExpExecArray | null
    while ((match = readCmdRe.exec(parsed.innerCommand)) !== null) {
      paths.push(match[1])
    }
  }

  if (parsed.type === "scp") {
    const remotePathRe =
      /^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*:(.+)$/

    // Check sources for remote paths
    if (parsed.scpSources) {
      for (const src of parsed.scpSources) {
        const m = remotePathRe.exec(src)
        if (m) paths.push(m[1])
      }
    }

    // Check destination for remote path
    if (parsed.scpDestination) {
      const m = remotePathRe.exec(parsed.scpDestination)
      if (m) paths.push(m[1])
    }
  }

  return paths
}

/**
 * Check if the inner command of an SSH command is in the bypass list.
 * SCP and SFTP are never bypassed (file transfers always need evaluation).
 * Interactive SSH (no inner command) is never bypassed.
 */
export function isInnerCommandBypassed(
  parsed: ParsedSshCommand,
  bypassedCommands: string[],
): boolean {
  if (parsed.type !== "ssh") return false

  if (!parsed.innerCommand) return false

  const inner = parsed.innerCommand.trimStart()
  return bypassedCommands.some((prefix) => inner.startsWith(prefix))
}

const RSYNC_REMOTE_PATH_RE = /^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*:/

const RCLONE_REMOTE_PATH_RE = /^[A-Za-z][A-Za-z0-9_-]*:/

function stripEnvVars(command: string): string {
  let cmd = command.trimStart()
  while (/^[A-Za-z_][A-Za-z0-9_]*=\S+\s/.test(cmd)) {
    cmd = cmd.replace(/^[A-Za-z_][A-Za-z0-9_]*=\S+\s+/, "")
  }
  return cmd
}

function hasRsyncRemote(command: string): boolean {
  const stripped = stripEnvVars(command)
  if (!stripped.startsWith("rsync")) return false

  const tokens = tokenize(stripped)
  if (tokens.length === 0 || tokens[0] !== "rsync") return false

  if (tokens.includes("-e") || tokens.some((t) => t.startsWith("-e="))) {
    return true
  }

  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i]
    if (tok.startsWith("-")) continue
    if (RSYNC_REMOTE_PATH_RE.test(tok)) return true
  }

  return false
}

function hasRcloneRemote(command: string): boolean {
  const stripped = stripEnvVars(command)
  if (!stripped.startsWith("rclone")) return false

  const tokens = tokenize(stripped)
  if (tokens.length === 0 || tokens[0] !== "rclone") return false

  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i]
    if (tok.startsWith("-")) continue
    if (RCLONE_REMOTE_PATH_RE.test(tok)) return true
  }

  return false
}

export function isRemoteCommand(command: string): boolean {
  if (!command || typeof command !== "string") return false

  const stripped = stripEnvVars(command.trim())

  if (stripped.startsWith("ssh") || stripped.startsWith("scp") || stripped.startsWith("sftp")) {
    return parseSshCommand(command) !== null
  }

  if (stripped.startsWith("rsync")) {
    return hasRsyncRemote(command)
  }

  if (stripped.startsWith("rclone")) {
    return hasRcloneRemote(command)
  }

  return false
}
