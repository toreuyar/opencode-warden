import { describe, test, expect } from "bun:test"
import { DetectionEngine } from "../src/detection/engine.js"
import { createDetectionEngine } from "../src/detection/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"

describe("DetectionEngine", () => {
  const engine = createDetectionEngine(DEFAULT_CONFIG)

  test("scan returns empty for clean input", () => {
    const result = engine.scan("This is a clean string with no secrets.")
    expect(result.hasDetections).toBe(false)
    expect(result.matches).toHaveLength(0)
    expect(result.redacted).toBe("This is a clean string with no secrets.")
  })

  test("scan detects and redacts OpenAI key", () => {
    const input = "My API key is sk-proj-abc123def456ghi789jkl012mno345pqr678stu901"
    const result = engine.scan(input)
    expect(result.hasDetections).toBe(true)
    expect(result.matches.length).toBeGreaterThan(0)
    expect(result.redacted).not.toContain("abc123def456")
    expect(result.redacted).toContain("[REDACTED]")
  })

  test("scan detects and redacts GitHub PAT", () => {
    const input = "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
    const result = engine.scan(input)
    expect(result.hasDetections).toBe(true)
    expect(result.redacted).toContain("[REDACTED]")
    expect(result.redacted).not.toContain("ABCDEFGHIJKLMNOPQRST")
  })

  test("scan detects RSA private key", () => {
    const input = `Some text
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWeZENr...
-----END RSA PRIVATE KEY-----
More text`
    const result = engine.scan(input)
    expect(result.hasDetections).toBe(true)
    expect(result.redacted).toContain("[REDACTED]")
    expect(result.redacted).not.toContain("MIIEowIBAAK")
  })

  test("scan detects multiple secrets in one input", () => {
    const input = `
      OpenAI: sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
      GitHub: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
      AWS: AKIAIOSFODNN7EXAMPLE
    `
    const result = engine.scan(input)
    expect(result.hasDetections).toBe(true)
    expect(result.matches.length).toBeGreaterThanOrEqual(3)
  })

  test("scan handles overlapping matches", () => {
    // If a JWT matches both JWT pattern and bearer token pattern, keep the longer match
    const input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    const result = engine.scan(input)
    expect(result.hasDetections).toBe(true)
  })

  test("hasSensitiveData returns true for sensitive input", () => {
    expect(
      engine.hasSensitiveData("key: sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
    ).toBe(true)
  })

  test("hasSensitiveData returns false for clean input", () => {
    expect(engine.hasSensitiveData("just a normal string")).toBe(false)
  })

  test("scan handles empty input", () => {
    const result = engine.scan("")
    expect(result.hasDetections).toBe(false)
    expect(result.redacted).toBe("")
  })

  test("scan detects email addresses", () => {
    const input = "Contact john.doe@example.com for more info"
    const result = engine.scan(input)
    expect(result.hasDetections).toBe(true)
    expect(result.redacted).toContain("[REDACTED]")
  })

  test("scan detects SSN", () => {
    const input = "SSN: 123-45-6789"
    const result = engine.scan(input)
    expect(result.hasDetections).toBe(true)
    expect(result.redacted).toContain("[REDACTED]")
  })

  test("scan detects MongoDB connection string with password", () => {
    const input = "mongodb://admin:p4ssw0rd@db.example.com:27017/mydb"
    const result = engine.scan(input)
    expect(result.hasDetections).toBe(true)
    expect(result.redacted).not.toContain("p4ssw0rd")
  })
})

describe("DetectionEngine - pattern management", () => {
  test("setPatterns replaces patterns", () => {
    const engine = new DetectionEngine([])
    expect(engine.hasSensitiveData("sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx")).toBe(false)

    engine.setPatterns([
      {
        id: "test",
        name: "Test",
        category: "api-keys",
        pattern: /sk-proj-[A-Za-z0-9]{20,}/g,
        redact: () => "[REDACTED]",
        confidence: "high",
      },
    ])
    expect(engine.hasSensitiveData("sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx")).toBe(true)
  })

  test("getPatterns returns copy", () => {
    const engine = new DetectionEngine([])
    const patterns = engine.getPatterns()
    expect(patterns).toEqual([])
    expect(patterns).not.toBe((engine as any).patterns)
  })
})
