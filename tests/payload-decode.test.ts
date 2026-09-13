import { describe, test, expect } from "bun:test"
import {
  extractDecodedPayloads,
  formatDecodedSection,
} from "../src/llm/payload-decode.js"
import { buildSafetyPrompt, DEFAULT_SAFETY_SYSTEM_PROMPT } from "../src/llm/prompts.js"

describe("extractDecodedPayloads", () => {
  test("C0.9 verbatim: double base64 chain decodes to rm -rf /", () => {
    const out = extractDecodedPayloads({
      command: 'echo "Y20wZ0xYSm1JQzg9" | base64 -d | base64 -d',
    })
    expect(out.length).toBeGreaterThanOrEqual(1)
    const main = out.find((p) => p.original === "Y20wZ0xYSm1JQzg9")!
    expect(main.methods).toEqual(["base64", "base64"])
    expect(main.result).toBe("rm -rf /")
    expect(main.printable).toBe(true)
  })

  test("single base64 with executor", () => {
    const out = extractDecodedPayloads({
      command: 'echo "cm0gLXJmIC8=" | base64 -d | sh',
    })
    const main = out.find((p) => p.original.startsWith("cm0gLXJmIC8"))!
    expect(main.methods).toEqual(["base64"])
    expect(main.result).toBe("rm -rf /")
  })

  test("no decoder present → no segments (no false positives on long words)", () => {
    const out = extractDecodedPayloads({
      command: "echo 'extraordinary organization matters'",
    })
    expect(out).toEqual([])
  })

  test("hex escapes decode", () => {
    const out = extractDecodedPayloads({
      command: "printf '\\x72\\x6d\\x20\\x2d\\x72\\x66'",
    })
    expect(out.some((p) => p.methods[0] === "hex-escapes" && p.result === "rm -rf")).toBe(true)
  })

  test("bare hex literal gated on xxd -r", () => {
    const withXxd = extractDecodedPayloads({
      command: "echo 726d202d7266202f | xxd -r -p",
    })
    expect(withXxd.some((p) => p.result === "rm -rf /")).toBe(true)

    // same-looking token without xxd → not reported (e.g. git SHA in a command)
    const noXxd = extractDecodedPayloads({
      command: "git checkout 726d202d7266202f",
    })
    expect(noXxd.some((p) => p.methods[0] === "hex-literal")).toBe(false)
  })

  test("rot13 idiom decodes quoted literal", () => {
    const out = extractDecodedPayloads({
      command: "echo 'ez -es /' | tr 'A-Za-z' 'N-ZA-Mn-za-m'",
    })
    expect(out.some((p) => p.result === "rm -rf /")).toBe(true)
  })

  test("non-printable result flagged, result empty", () => {
    // "/wAAAAAAAAA" = 0xFF followed by eight NULs — valid base64, non-printable
    const out = extractDecodedPayloads({
      command: 'echo "/wAAAAAAAAA" | base64 -d',
    })
    const main = out.find((p) => p.original === "/wAAAAAAAAA")!
    expect(main.printable).toBe(false)
    expect(main.result).toBe("")
    expect(main.bytes).toBeGreaterThan(0)
  })
})

describe("formatDecodedSection", () => {
  test("empty when nothing decoded", () => {
    expect(formatDecodedSection([])).toBe("")
  })

  test("contains ground-truth header and chain", () => {
    const s = formatDecodedSection(
      extractDecodedPayloads({
        command: 'echo "Y20wZ0xYSm1JQzg9" | base64 -d | base64 -d',
      }),
    )
    expect(s).toContain("PRE-DECODED PAYLOADS")
    expect(s).toContain("base64 ×2")
    expect(s).toContain("rm -rf /")
    expect(s).toContain("Never decode payloads yourself")
  })
})

describe("buildSafetyPrompt integration", () => {
  test("encoded command gets pre-decoded section appended", () => {
    const prompt = buildSafetyPrompt("bash", {
      command: 'echo "Y20wZ0xYSm1JQzg9" | base64 -d | base64 -d',
    })
    expect(prompt).toContain("PRE-DECODED PAYLOADS")
    expect(prompt).toContain("rm -rf /")
  })

  test("plain command prompt unchanged (no section)", () => {
    const prompt = buildSafetyPrompt("bash", { command: "docker ps -a" })
    expect(prompt).not.toContain("PRE-DECODED PAYLOADS")
  })

  test("reworded executor rule present in system prompt", () => {
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("judge by PIPELINE STRUCTURE")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).toContain("Do NOT decode payloads character-by-character")
    expect(DEFAULT_SAFETY_SYSTEM_PROMPT).not.toContain("Decode the payload mentally")
  })
})
