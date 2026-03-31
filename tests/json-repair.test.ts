import { describe, it, expect } from "bun:test"
import { tryParseJsonObject } from "../src/utils/json-repair.js"

describe("tryParseJsonObject", () => {
  it("parses valid JSON directly", () => {
    const result = tryParseJsonObject('{"safe": true, "riskLevel": "low"}')
    expect(result).toEqual({ safe: true, riskLevel: "low" })
  })

  it("extracts JSON from surrounding text", () => {
    const result = tryParseJsonObject('Some text before {"key": "value"} and after')
    expect(result).toEqual({ key: "value" })
  })

  it("returns null when no JSON block found", () => {
    expect(tryParseJsonObject("no json here")).toBeNull()
  })

  it("returns null for empty string", () => {
    expect(tryParseJsonObject("")).toBeNull()
  })

  it("repairs unescaped double quotes inside string values", () => {
    // This is the exact pattern from the 3B model's safety evaluation response
    const malformed = `{
  "safe": true,
  "riskLevel": "low",
  "riskDimensions": ["privilege-escalation"],
  "explanation": "The command operates within the explicitly enabled DevOps operational profiles. This is covered under "security-monitoring" and "log-review" profiles. Overall, it is a standard monitoring operation.",
  "recommendation": "allow"
}`
    const result = tryParseJsonObject(malformed)
    expect(result).not.toBeNull()
    expect(result!.safe).toBe(true)
    expect(result!.riskLevel).toBe("low")
    expect(result!.recommendation).toBe("allow")
    expect(result!.riskDimensions).toEqual(["privilege-escalation"])
    expect((result!.explanation as string)).toContain("security-monitoring")
    expect((result!.explanation as string)).toContain("log-review")
  })

  it("repairs multiple unescaped quotes in explanation", () => {
    const malformed = `{
  "safe": true,
  "riskLevel": "low",
  "explanation": "Command "systemctl status" is a "read-only" operation under "service-status" profile.",
  "recommendation": "allow"
}`
    const result = tryParseJsonObject(malformed)
    expect(result).not.toBeNull()
    expect(result!.safe).toBe(true)
    expect(result!.recommendation).toBe("allow")
    expect((result!.explanation as string)).toContain("systemctl status")
    expect((result!.explanation as string)).toContain("read-only")
    expect((result!.explanation as string)).toContain("service-status")
  })

  it("handles properly escaped quotes without breaking them", () => {
    const valid = `{
  "explanation": "This uses \\"sudo\\" which requires elevation.",
  "safe": true
}`
    const result = tryParseJsonObject(valid)
    expect(result).not.toBeNull()
    expect((result!.explanation as string)).toContain('"sudo"')
  })

  it("handles nested arrays and objects", () => {
    const json = `{
  "riskDimensions": ["privilege-escalation", "excessive-collection"],
  "safe": false,
  "nested": {"key": "value"}
}`
    const result = tryParseJsonObject(json)
    expect(result).not.toBeNull()
    expect(result!.riskDimensions).toEqual(["privilege-escalation", "excessive-collection"])
    expect(result!.safe).toBe(false)
  })

  it("handles sanitizer response format", () => {
    const json = `{
  "sanitized": "sudo: crowdsec-cli: command not found",
  "detections": []
}`
    const result = tryParseJsonObject(json)
    expect(result).not.toBeNull()
    expect(result!.sanitized).toBe("sudo: crowdsec-cli: command not found")
    expect(result!.detections).toEqual([])
  })

  it("repairs sanitizer response with unescaped quotes in sanitized field", () => {
    const malformed = `{
  "sanitized": "User "admin" logged in from "192.168.1.1" at 10:00.",
  "detections": []
}`
    const result = tryParseJsonObject(malformed)
    expect(result).not.toBeNull()
    expect((result!.sanitized as string)).toContain("admin")
    expect((result!.sanitized as string)).toContain("192.168.1.1")
  })

  it("handles JSON wrapped in markdown code block", () => {
    const wrapped = '```json\n{"safe": true, "riskLevel": "none"}\n```'
    const result = tryParseJsonObject(wrapped)
    expect(result).not.toBeNull()
    expect(result!.safe).toBe(true)
  })
})
