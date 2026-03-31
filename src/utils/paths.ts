import { parseSshCommand, extractRemoteFilePaths } from "./ssh.js"

const RSYNC_REMOTE_PATH_RE = /^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*:(.+)$/

const RCLONE_REMOTE_PATH_RE = /^[A-Za-z][A-Za-z0-9_-]*:(.+)$/

function extractRsyncRemotePaths(command: string): string[] {
  const paths: string[] = []
  const tokens = tokenizeCommand(command)
  
  if (tokens.length === 0 || tokens[0] !== "rsync") return []
  
  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i]
    if (tok.startsWith("-")) continue
    
    const match = RSYNC_REMOTE_PATH_RE.exec(tok)
    if (match) {
      paths.push(match[1])
    }
  }
  
  return paths
}

function extractRcloneRemotePaths(command: string): string[] {
  const paths: string[] = []
  const tokens = tokenizeCommand(command)
  
  if (tokens.length === 0 || tokens[0] !== "rclone") return []
  
  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i]
    if (tok.startsWith("-")) continue
    
    const match = RCLONE_REMOTE_PATH_RE.exec(tok)
    if (match) {
      paths.push(match[1])
    }
  }
  
  return paths
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

    current += ch
  }

  if (current.length > 0) {
    tokens.push(current)
  }

  return tokens
}

/**
 * Check if a file path matches any of the blocked patterns.
 * Whitelist takes priority over blocklist.
 */
export function isBlockedPath(
  filePath: string,
  blockedPatterns: string[],
  whitelistedPatterns: string[],
): boolean {
  // Normalize path
  const normalized = filePath.replace(/\\/g, "/")

  // Check whitelist first (takes priority)
  for (const pattern of whitelistedPatterns) {
    if (matchGlob(normalized, pattern)) {
      return false
    }
  }

  // Check blocklist
  for (const pattern of blockedPatterns) {
    if (matchGlob(normalized, pattern)) {
      return true
    }
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
 * Extract remote file paths from SSH/SCP commands in bash tool args.
 * Returns empty array for non-SSH commands.
 */
export function extractRemoteFilePathsFromArgs(
  tool: string,
  args: Record<string, unknown>,
): string[] {
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
