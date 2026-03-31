/**
 * Command pattern matching utilities for the allowed operations bypass mechanism.
 *
 * Three categories of commands:
 * A. Simple commands (no shell metacharacters) → check bypass prefixes + patterns
 * B. Pipe chains (only |, no other metacharacters) → split and check each segment
 * C. Dangerous chaining (;, &&, ||, `, $(), >, <, &, newlines) → always go to LLM
 */

/**
 * Regex matching safe shell redirections that can be stripped before
 * checking for dangerous metacharacters.
 *
 * Matches:
 * - 2>/dev/null, 2>>/dev/null, >/dev/null, 1>/dev/null (stream to /dev/null)
 * - 2>&1, 1>&2 (stream merging between file descriptors)
 * - &>/dev/null, &>>/dev/null (bash shorthand: both streams to /dev/null)
 */
const SAFE_REDIRECT_RE = /\d*>{1,2}\s*\/dev\/null|\d*>&\d+|&>{1,2}\s*\/dev\/null/g

/**
 * Strip safe shell redirections from a command string.
 * Only redirections to /dev/null and stream merges (2>&1) are considered safe.
 * Arbitrary file redirections (> /etc/passwd) remain and will be caught.
 */
export function stripSafeRedirects(command: string): string {
  return command.replace(SAFE_REDIRECT_RE, " ")
}

/**
 * Regex matching dangerous shell metacharacters — everything except a single pipe.
 * Catches: ; & ` < > \n \r $(
 * Note: || is handled separately before pipe splitting.
 */
const DANGEROUS_METACHAR_RE = /[;&`<>\n\r]|\$\(/

/**
 * Safe pipe targets — read-only data-processing commands that are safe to
 * receive piped data. These commands only transform/filter stdin and produce
 * output on stdout without side effects.
 *
 * Explicitly excluded:
 * - xargs: executes arbitrary commands with stdin as arguments
 * - tee: writes to files (e.g., cat file | tee /etc/passwd)
 * - awk: can execute system commands via system()
 */
const SAFE_PIPE_TARGETS = new Set([
  "grep",
  "head",
  "tail",
  "sort",
  "wc",
  "cut",
  "uniq",
  "tr",
  "less",
  "more",
  "sed",
  "column",
  "fmt",
  "nl",
  "rev",
  "fold",
  "jq",
])

/**
 * Escape special regex characters in a string, except for *.
 */
function escapeRegexExceptStar(str: string): string {
  return str.replace(/[.+?^${}()|[\]\\]/g, "\\$&")
}

/**
 * Compile a glob-style command pattern into a RegExp.
 * - `*` matches any sequence of characters (including none)
 * - All other regex special characters are escaped
 * - Pattern is anchored at the start (^) but not the end, so
 *   "systemctl status *" matches "systemctl status nginx --no-pager"
 */
export function compileCommandPattern(pattern: string): RegExp {
  const escaped = escapeRegexExceptStar(pattern)
  const regexStr = escaped.replace(/\*/g, ".*")
  return new RegExp(`^${regexStr}$`)
}

/**
 * Check if a command matches any of the compiled allowed-operation patterns.
 */
export function isAllowedOperation(
  command: string,
  compiledPatterns: RegExp[],
): boolean {
  const trimmed = command.trimStart()
  return compiledPatterns.some((re) => re.test(trimmed))
}

/**
 * Check whether a command string contains dangerous shell metacharacters
 * (anything that enables chaining, substitution, or redirection beyond simple pipes).
 */
export function hasDangerousMetachars(command: string): boolean {
  const cleaned = stripSafeRedirects(command)
  return DANGEROUS_METACHAR_RE.test(cleaned)
}

/**
 * Check if a pipe segment starts with a safe pipe target command.
 */
export function isSafePipeTarget(segment: string): boolean {
  const trimmed = segment.trimStart()
  const firstWord = trimmed.split(/\s/)[0]
  return SAFE_PIPE_TARGETS.has(firstWord)
}

/**
 * Strip a leading `sudo` (with optional flags) from a command.
 *
 * Handles common sudo flags: -u user, -E, -H, -n, -S, -i, -b, -k, -K, -l, -v, --
 * Does NOT strip sudo that appears mid-command.
 *
 * Examples:
 *   "sudo cscli decisions list"         → "cscli decisions list"
 *   "sudo -u root cscli decisions list" → "cscli decisions list"
 *   "sudo -E -H tail /var/log/syslog"   → "tail /var/log/syslog"
 *   "echo hello"                         → "echo hello"
 */
export function stripSudo(command: string): string {
  const trimmed = command.trimStart()
  if (!trimmed.startsWith("sudo")) return trimmed

  // Must be exactly "sudo" followed by whitespace or end-of-string
  if (trimmed.length > 4 && !/\s/.test(trimmed[4])) return trimmed

  // Tokenize after "sudo " and consume flags
  const rest = trimmed.slice(4).trimStart()
  if (!rest) return ""

  // Flags that take no argument
  const noArgFlags = new Set(["-E", "-H", "-n", "-S", "-i", "-b", "-k", "-K", "-l", "-v", "--preserve-env", "--non-interactive", "--stdin", "--login", "--background", "--reset-timestamp", "--remove-timestamp", "--list", "--validate"])
  // Flags that consume the next token as their argument
  const argFlags = new Set(["-u", "-g", "-C", "-D", "-p", "-r", "-t", "--user", "--group", "--close-from", "--directory", "--prompt", "--role", "--type"])

  const tokens = rest.split(/\s+/)
  let i = 0

  while (i < tokens.length) {
    const token = tokens[i]

    if (token === "--") {
      // -- ends flag processing, everything after is the command
      i++
      break
    }

    if (noArgFlags.has(token)) {
      i++
      continue
    }

    if (argFlags.has(token)) {
      // Skip this flag and its argument
      i += 2
      continue
    }

    // Check for combined -u<user> form (flag with value joined)
    const combinedMatch = token.match(/^(-[ugCDprt])(.+)$/)
    if (combinedMatch && argFlags.has(combinedMatch[1])) {
      i++
      continue
    }

    // Not a recognized flag — this is the start of the actual command
    break
  }

  return tokens.slice(i).join(" ")
}

/**
 * Evaluate whether a piped command chain is safe to bypass.
 *
 * Rules:
 * - Rejects if `||` is present (logical OR, not a pipe)
 * - First segment must match a bypass prefix or allowed pattern
 * - Subsequent segments must start with a safe pipe target
 *
 * @returns true if all segments are safe and the command can bypass LLM
 */
export function isPipedCommandSafe(
  command: string,
  bypassPrefixes: string[],
  compiledPatterns: RegExp[],
): boolean {
  // Reject || (logical OR) — it's not a pipe
  if (command.includes("||")) return false

  const segments = command.split("|").map((s) => s.trim())
  if (segments.length < 2) return false

  // First segment: must match bypass prefix or allowed pattern
  const first = segments[0]
  const firstMatchesPrefix = bypassPrefixes.some((prefix) =>
    first.trimStart().startsWith(prefix),
  )
  const firstMatchesPattern = isAllowedOperation(first, compiledPatterns)

  if (!firstMatchesPrefix && !firstMatchesPattern) return false

  // Subsequent segments: must all be safe pipe targets
  for (let i = 1; i < segments.length; i++) {
    if (!isSafePipeTarget(segments[i])) return false
  }

  return true
}
