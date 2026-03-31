import { readFileSync, existsSync, statSync } from "fs"
import { resolve, extname, basename } from "path"

/**
 * Extract file paths that a bash command would execute.
 *
 * Detects:
 * - Direct execution: `/path/to/script`, `./script.sh`
 * - Interpreter invocation: `bash script.sh`, `python3 file.py`
 * - Source commands: `source file`, `. file`
 * - Pipe-to-shell: `cat file | bash`, `cat file | sh`
 */
export function extractExecutedFilePaths(
  command: string,
  interpreters: string[],
): string[] {
  const paths: string[] = []
  const cwd = process.cwd()

  // Split on && ; || to handle chained commands
  const segments = command.split(/\s*(?:&&|\|\||;)\s*/)

  for (const segment of segments) {
    const trimmed = segment.trim()
    if (!trimmed) continue

    // Check for pipe-to-shell: `cat file | bash`
    if (trimmed.includes("|")) {
      const pipeParts = trimmed.split("|").map((p) => p.trim())
      for (let i = 0; i < pipeParts.length - 1; i++) {
        const rightPart = pipeParts[i + 1]
        if (!rightPart) continue
        const rightTokens = tokenize(rightPart)
        const rightCmd = rightTokens[0]
        if (rightCmd && isInterpreter(rightCmd, interpreters)) {
          // Left side feeds into an interpreter — extract the cat/echo target
          const catTarget = extractCatTarget(pipeParts[i])
          if (catTarget) {
            const resolved = resolveFilePath(catTarget, cwd)
            if (resolved) paths.push(resolved)
          }
        }
      }
      // Also check each pipe segment individually for direct/interpreter patterns
      for (const part of pipeParts) {
        extractFromSingleCommand(part.trim(), interpreters, cwd, paths)
      }
    } else {
      extractFromSingleCommand(trimmed, interpreters, cwd, paths)
    }
  }

  // Deduplicate
  return [...new Set(paths)]
}

/**
 * Check if a file path is under a trusted system directory.
 */
export function isSystemPath(filePath: string, systemPaths: string[]): boolean {
  return systemPaths.some((sp) => filePath.startsWith(sp))
}

/**
 * Detect if a file is a binary by checking magic bytes.
 * Returns true for ELF, Mach-O binaries and files with excessive null bytes.
 * Returns false for shebang scripts (#!).
 */
export function isBinaryFile(filePath: string): boolean {
  try {
    const fd = readFileSync(filePath, { flag: "r" })
    const header = fd.subarray(0, 512)

    if (header.length < 4) return false

    // Shebang = script, not binary
    if (header[0] === 0x23 && header[1] === 0x21) return false // #!

    // ELF magic: 0x7f ELF
    if (
      header[0] === 0x7f &&
      header[1] === 0x45 &&
      header[2] === 0x4c &&
      header[3] === 0x46
    ) {
      return true
    }

    // Mach-O magic bytes
    const machOMagics = [
      0xfeedface, // 32-bit
      0xfeedfacf, // 64-bit
      0xcefaedfe, // 32-bit reversed
      0xcffaedfe, // 64-bit reversed
      0xcafebabe, // Universal binary
    ]
    const magic32 =
      (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3]
    if (machOMagics.includes(magic32 >>> 0)) return true

    // Null-byte heuristic: more than 10% null bytes in first 512 bytes = binary
    let nullCount = 0
    for (let i = 0; i < header.length; i++) {
      if (header[i] === 0) nullCount++
    }
    if (nullCount > header.length * 0.1) return true

    return false
  } catch {
    // Can't read = treat as unknown (caller decides)
    return false
  }
}

/**
 * Read file content, truncated to maxSize bytes.
 * Returns null if file doesn't exist or can't be read.
 */
export function readFileContent(
  filePath: string,
  maxSize: number,
): { content: string; truncated: boolean } | null {
  try {
    if (!existsSync(filePath)) return null

    const stat = statSync(filePath)
    if (!stat.isFile()) return null

    const buffer = readFileSync(filePath)
    if (buffer.length <= maxSize) {
      return { content: buffer.toString("utf-8"), truncated: false }
    }
    return {
      content: buffer.subarray(0, maxSize).toString("utf-8"),
      truncated: true,
    }
  } catch {
    return null
  }
}

/**
 * Check if a file has an executable script extension.
 */
export function hasExecutableExtension(
  filePath: string,
  extensions: string[],
): boolean {
  const ext = extname(filePath).toLowerCase()
  return extensions.includes(ext)
}

// ─── Internal Helpers ───

/**
 * Quote-aware tokenizer. Splits on whitespace but respects single/double quotes.
 */
function tokenize(command: string): string[] {
  const tokens: string[] = []
  let current = ""
  let inSingle = false
  let inDouble = false
  let escaped = false

  for (const ch of command) {
    if (escaped) {
      current += ch
      escaped = false
      continue
    }
    if (ch === "\\") {
      escaped = true
      current += ch
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
    if (!inSingle && !inDouble && /\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push(current)
        current = ""
      }
      continue
    }
    current += ch
  }
  if (current.length > 0) tokens.push(current)
  return tokens
}

/**
 * Check if a command name is a known interpreter (by basename).
 */
function isInterpreter(cmd: string, interpreters: string[]): boolean {
  const name = basename(cmd)
  return interpreters.includes(name)
}

/**
 * Extract the file target from a `cat`/`<` command.
 * e.g., `cat script.sh` → `script.sh`
 */
function extractCatTarget(command: string): string | null {
  const tokens = tokenize(command.trim())
  if (tokens.length === 0) return null
  const cmd = basename(tokens[0])
  if (cmd === "cat" && tokens.length >= 2) {
    // Return first non-flag argument
    for (let i = 1; i < tokens.length; i++) {
      if (!tokens[i].startsWith("-")) return tokens[i]
    }
  }
  return null
}

/**
 * Extract executed file paths from a single command (no pipes, no chains).
 */
function extractFromSingleCommand(
  command: string,
  interpreters: string[],
  cwd: string,
  results: string[],
): void {
  const tokens = tokenize(command)
  if (tokens.length === 0) return

  const cmd = tokens[0]

  // Skip if command is a pure shell builtin with no file reference
  if (!cmd) return

  // `source file` or `. file`
  if ((cmd === "source" || cmd === ".") && tokens.length >= 2) {
    const resolved = resolveFilePath(tokens[1], cwd)
    if (resolved) results.push(resolved)
    return
  }

  // Interpreter invocation: `bash script.sh`, `python3 file.py`
  if (isInterpreter(cmd, interpreters)) {
    // Find the first non-flag argument as the script file
    for (let i = 1; i < tokens.length; i++) {
      const token = tokens[i]
      // Skip flags like -c, -e, --version, etc.
      if (token.startsWith("-")) {
        // -c means inline script, not file execution
        if (token === "-c") return
        continue
      }
      const resolved = resolveFilePath(token, cwd)
      if (resolved) results.push(resolved)
      return
    }
    return
  }

  // Direct execution: `./script.sh`, `/tmp/script.sh`, `~/script.sh`
  if (
    cmd.startsWith("/") ||
    cmd.startsWith("./") ||
    cmd.startsWith("../") ||
    cmd.startsWith("~/")
  ) {
    const resolved = resolveFilePath(cmd, cwd)
    if (resolved) results.push(resolved)
  }
}

/**
 * Resolve a file path, handling `~/` and relative paths.
 */
function resolveFilePath(filePath: string, cwd: string): string | null {
  if (!filePath) return null

  let resolved: string
  if (filePath.startsWith("~/")) {
    const home = process.env.HOME || process.env.USERPROFILE || "~"
    resolved = resolve(home, filePath.slice(2))
  } else if (filePath.startsWith("/")) {
    resolved = filePath
  } else {
    resolved = resolve(cwd, filePath)
  }

  return resolved
}
