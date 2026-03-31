import { describe, test, expect } from "bun:test"
import { maskWithEnds, maskFull } from "../src/detection/redactor.js"

describe("redactor", () => {
  test("maskWithEnds always returns [REDACTED]", () => {
    expect(maskWithEnds("sk-abc123xyz", "sk-", 4)).toBe("[REDACTED]")
  })

  test("maskWithEnds ignores prefix and showLast args", () => {
    expect(maskWithEnds("secret_value", "", 0)).toBe("[REDACTED]")
    expect(maskWithEnds("anything", "any", 10)).toBe("[REDACTED]")
  })

  test("maskFull returns [REDACTED]", () => {
    expect(maskFull()).toBe("[REDACTED]")
  })
})
