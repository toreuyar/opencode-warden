/**
 * Redact a matched value with a standard [REDACTED] marker.
 * Kept as a function for backward compatibility with pattern definitions.
 */
export function maskWithEnds(
  _value: string,
  _prefix: string,
  _showLast: number,
): string {
  return "[REDACTED]"
}

/**
 * Fully mask a string.
 */
export function maskFull(): string {
  return "[REDACTED]"
}
