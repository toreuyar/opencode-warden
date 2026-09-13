// ─── Deterministic payload decoder ───────────────────────────────────────────
// Extracts and decodes encoded segments (base64 chains, hex, octal escapes,
// ROT13) from tool-call arguments BEFORE the LLM sees them. The decoded
// plaintext is injected into the prompt as ground truth so the model never
// performs mental decoding — which provably spirals into bit-counting loops
// on this model family (see server-management.md 2026-09-09).
//
// Design rules:
//  - Decoding a string is a pure data transformation; nothing executes.
//  - Base64 decoding is gated on an explicit decoder command being present
//    (e.g. `base64 -d`), which kills false positives on ordinary long words.
//  - Multi-stage chains decode repeatedly, capped at MAX_DEPTH.

export interface DecodedPayload {
  field: string // argument field the segment was found in
  original: string // encoded segment as it appeared
  methods: string[] // one entry per successful decode stage
  result: string // final plaintext ("" when non-printable)
  printable: boolean
  bytes: number // decoded byte count of the final stage
}

const MAX_DEPTH = 5
const MAX_SEGMENTS = 8
const MIN_ARG_LENGTH = 12

// ─── base64 ────────────────────────────────────────────────────────────────

function looksBase64(s: string): boolean {
  if (s.length < 8 || s.length % 4 === 1) return false
  return /^[A-Za-z0-9+/]+={0,2}$/.test(s)
}

function b64Decode(s: string): string | null {
  if (!looksBase64(s)) return null
  const buf = Buffer.from(s, "base64")
  if (buf.length === 0) return null
  // round-trip validation rejects ordinary alphanumeric words
  const rt = buf.toString("base64").replace(/=+$/, "")
  if (rt !== s.replace(/=+$/, "")) return null
  return buf.toString("utf8")
}

function b64Depth(command: string): number {
  const explicit = command.match(/base64[^|;]{0,24}?(-d|--decode|-D)/g)?.length ?? 0
  const openssl = command.match(/openssl[^|;]{0,40}base64[^|;]{0,12}(-d|--decode|-D)/g)?.length ?? 0
  return Math.min(explicit + openssl, MAX_DEPTH)
}

// ─── rot13 ─────────────────────────────────────────────────────────────────

function rot13(s: string): string {
  let out = ""
  for (const ch of s) {
    const c = ch.charCodeAt(0)
    if (c >= 65 && c <= 90) out += String.fromCharCode(65 + ((c - 65 + 13) % 26)) // A-Z
    else if (c >= 97 && c <= 122) out += String.fromCharCode(97 + ((c - 97 + 13) % 26)) // a-z
    else out += ch
  }
  return out
}

function hasRot13Idiom(command: string): boolean {
  // matches: tr 'A-Za-z' 'N-ZA-Mn-za-m'  (single or double quoted)
  return /tr\s+['"][A-Za-z]-[A-Za-z][A-Za-z]-[A-Za-z]['"]\s+['"][Nn]-[Zz][Aa]-[Mm][Nn]-[Zz][Aa]-[Mm]['"]/.test(command)
}

// ─── hex / octal escapes (intrinsic evidence — no gate needed) ─────────────

function decodeHexEscapes(s: string): string | null {
  const m = s.match(/(?:\\x[0-9a-fA-F]{2}){2,}/)
  if (!m) return null
  const hex = m[0].replace(/\\x/g, "")
  return Buffer.from(hex, "hex").toString("utf8")
}

function decodeOctalEscapes(s: string): string | null {
  const m = s.match(/(?:\\[0-7]{3}){2,}/)
  if (!m) return null
  const bytes = m[0].match(/[0-7]{3}/g)!.map((o) => parseInt(o, 8))
  return Buffer.from(bytes).toString("utf8")
}

function decodeHexLiteral(s: string): string | null {
  // bare hex literal adjacent to an xxd -r style decoder
  const m = s.match(/["'\s]([0-9a-fA-F]{8,})["'\s|]/)
  if (!m || m[1].length % 2 !== 0) return null
  return Buffer.from(m[1], "hex").toString("utf8")
}

// ─── printable check ───────────────────────────────────────────────────────

function printableRatio(s: string): number {
  if (s.length === 0) return 1
  let ok = 0
  for (const ch of s) {
    const c = ch.charCodeAt(0)
    if ((c >= 32 && c < 127) || c === 10 || c === 9) ok++
  }
  return ok / s.length
}

function displaySafe(s: string, max = 120): string {
  let out = ""
  for (const ch of s) {
    const c = ch.charCodeAt(0)
    out += c >= 32 && c < 127 ? ch : `\\x${c.toString(16).padStart(2, "0")}`
    if (out.length >= max) break
  }
  return out
}

// ─── main extraction ───────────────────────────────────────────────────────

export function extractDecodedPayloads(args: Record<string, unknown>): DecodedPayload[] {
  const found: DecodedPayload[] = []

  for (const [field, value] of Object.entries(args)) {
    if (typeof value !== "string" || value.length < MIN_ARG_LENGTH) continue
    const seen = new Set<string>()

    // base64 chains — gated on decoder presence, depth = number of decoders
    const depth = b64Depth(value)
    if (depth > 0) {
      for (const tok of value.match(/[A-Za-z0-9+/]{8,}={0,2}/g) ?? []) {
        if (seen.has(tok)) continue
        let cur = tok
        const methods: string[] = []
        for (let i = 0; i < depth; i++) {
          const next = b64Decode(cur)
          if (next === null) break
          methods.push("base64")
          cur = next
          if (!looksBase64(cur)) break
        }
        if (methods.length === 0) continue
        seen.add(tok)
        const printable = printableRatio(cur) >= 0.85
        found.push({
          field,
          original: tok,
          methods,
          result: printable ? cur : "",
          printable,
          bytes: Buffer.byteLength(cur, "utf8"),
        })
      }
    }

    // ROT13 — gated on the tr idiom; applied to quoted literals
    // (skips tr's own character-class arguments like 'A-Za-z' / 'N-ZA-Mn-za-m')
    if (hasRot13Idiom(value)) {
      for (const q of value.match(/['"]([^'"]{8,})['"]/g) ?? []) {
        const inner = q.slice(1, -1)
        if (seen.has(inner)) continue
        if (/^[A-Za-z]-[A-Za-z]/.test(inner)) continue // class-like, not payload
        const decoded = rot13(inner)
        if (decoded === inner) continue
        seen.add(inner)
        found.push({
          field,
          original: inner,
          methods: ["rot13"],
          result: decoded,
          printable: printableRatio(decoded) >= 0.85,
          bytes: Buffer.byteLength(decoded, "utf8"),
        })
      }
    }

    // hex / octal escapes — intrinsic evidence
    for (const [method, fn] of [
      ["hex-escapes", decodeHexEscapes],
      ["octal-escapes", decodeOctalEscapes],
      // bare hex literals — gated on an xxd-style reversal decoder being present
      ...( /xxd\s+[^|]{0,16}-r/.test(value) ? ([["hex-literal", decodeHexLiteral]] as const) : ([] as const) ),
    ] as const) {
      const decoded = fn(value)
      if (decoded && decoded.length > 0) {
        const key = method + decoded
        if (seen.has(key)) continue
        seen.add(key)
        const printable = printableRatio(decoded) >= 0.85
        found.push({
          field,
          original: value.slice(0, 60),
          methods: [method],
          result: printable ? decoded : "",
          printable,
          bytes: Buffer.byteLength(decoded, "utf8"),
        })
      }
    }

    if (found.length >= MAX_SEGMENTS) break
  }

  return found.slice(0, MAX_SEGMENTS)
}

// ─── prompt section ────────────────────────────────────────────────────────

export function formatDecodedSection(payloads: DecodedPayload[]): string {
  if (payloads.length === 0) return ""
  const lines = payloads.map((p) => {
    const chain = p.methods.length > 1 ? `${p.methods[0]} ×${p.methods.length}` : p.methods[0]
    const result = p.printable
      ? `"${displaySafe(p.result)}"`
      : `<non-printable/binary, ${p.bytes} bytes — treat as opaque>`
    return `- ${p.field}: "${displaySafe(p.original, 60)}" → (${chain}) → ${result}`
  })
  return [
    "",
    "═══ PRE-DECODED PAYLOADS — decoded deterministically by the system; treat as ground truth. Never decode payloads yourself. ═══",
    ...lines,
    "",
  ].join("\n")
}
