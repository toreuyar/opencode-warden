/**
 * Strip common LLM reasoning/thinking wrappers before extracting JSON.
 * Many models (Nemotron, DeepSeek, Qwen, etc.) emit ⟨thinking⟩...⟩ or
 * <thinking>...</thinking> blocks before the actual response content.
 * If the thinking block consumes all available tokens, no JSON is emitted.
 */
function stripThinkingBlocks(text: string): string {
  // Unicode angle brackets: ⟨thinking⟩...⟩ (U+27E8 / U+27E9)
  let cleaned = text.replace(/\u27E8thinking\u27E9[\s\S]*?\u27E9/g, "")
  // Also handle cases where the closing ⟩ is missing (truncated thinking)
  cleaned = cleaned.replace(/\u27E8thinking\u27E9[\s\S]*/g, "")
  // XML-style: <thinking>...</thinking>
  cleaned = cleaned.replace(/<thinking>[\s\S]*?<\/thinking>/g, "")
  // Truncated XML thinking
  cleaned = cleaned.replace(/<thinking>[\s\S]*/g, "")
  return cleaned.trim()
}

/**
 * Attempt to parse a JSON object from a string that may contain
 * malformed JSON (e.g., unescaped double quotes inside string values).
 *
 * Strategy:
 * 1. Strip reasoning/thinking wrappers
 * 2. Extract the outermost {...} block
 * 3. Try JSON.parse directly
 * 4. If that fails, repair unescaped quotes and retry
 *
 * Returns the parsed object or null if all attempts fail.
 */
export function tryParseJsonObject(raw: string): Record<string, unknown> | null {
  // Strip thinking blocks that some models emit before JSON
  const stripped = stripThinkingBlocks(raw)

  // Try stripped version first, fall back to raw if stripping removed everything
  const text = stripped.length > 0 ? stripped : raw

  let jsonMatch = text.match(/\{[\s\S]*\}/)

  // If no closing brace found, the LLM may have truncated output.
  // Try appending closing braces to recover partial JSON.
  if (!jsonMatch) {
    const openBrace = text.indexOf("{")
    if (openBrace === -1) return null
    // Count unmatched opening braces and append closers
    const partial = text.slice(openBrace)
    let depth = 0
    for (const ch of partial) {
      if (ch === "{") depth++
      else if (ch === "}") depth--
    }
    const repaired = partial + '}'.repeat(Math.max(depth, 1))
    jsonMatch = repaired.match(/\{[\s\S]*\}/)
    if (!jsonMatch) return null
  }

  const jsonStr = jsonMatch[0]

  // Fast path: try direct parse
  try {
    return JSON.parse(jsonStr)
  } catch {
    // Fall through to repair
  }

  // Repair: fix unescaped quotes within string values
  try {
    const repaired = repairJsonQuotes(jsonStr)
    return JSON.parse(repaired)
  } catch {
    // Fall through to truncation repair
  }

  // Truncation repair: try closing an open string value + missing braces
  try {
    let truncated = jsonStr
    // If the string ends mid-value (odd number of unescaped quotes), close it
    let quoteCount = 0
    for (let i = 0; i < truncated.length; i++) {
      if (truncated[i] === '"' && (i === 0 || truncated[i - 1] !== '\\')) quoteCount++
    }
    if (quoteCount % 2 !== 0) truncated += '"'
    // Ensure closing brace
    if (!truncated.endsWith('}')) truncated += '}'
    return JSON.parse(truncated)
  } catch {
    return null
  }
}

/**
 * Walk the JSON string character-by-character, tracking whether we're
 * inside a string value. When inside a string, check if each `"` is
 * structural (ends the string) or unescaped (should be escaped).
 *
 * A `"` inside a string is structural if the next non-whitespace
 * character is one of: `:` `,` `}` `]` or end-of-string.
 * Otherwise it's an unescaped quote and gets escaped as `\"`.
 */
function repairJsonQuotes(json: string): string {
  const result: string[] = []
  let inString = false
  let i = 0

  while (i < json.length) {
    const ch = json[i]

    // Handle existing escape sequences inside strings
    if (inString && ch === "\\") {
      result.push(ch)
      i++
      if (i < json.length) {
        result.push(json[i])
        i++
      }
      continue
    }

    if (ch === '"') {
      if (!inString) {
        // Entering a string
        inString = true
        result.push(ch)
        i++
      } else {
        // In a string — is this quote structural (end of string) or unescaped?
        // Look ahead past whitespace for a structural character
        let j = i + 1
        while (j < json.length && /\s/.test(json[j])) j++

        const next = json[j]
        if (
          next === undefined ||
          next === ":" ||
          next === "," ||
          next === "}" ||
          next === "]"
        ) {
          // Structural: this ends the string
          inString = false
          result.push(ch)
          i++
        } else {
          // Unescaped quote inside string value — escape it
          result.push("\\")
          result.push(ch)
          i++
        }
      }
    } else {
      result.push(ch)
      i++
    }
  }

  return result.join("")
}
