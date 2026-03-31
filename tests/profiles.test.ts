import { describe, test, expect } from "bun:test"
import {
  BUILTIN_PROFILES,
  resolveAllowedPatterns,
  getActiveProfileDescriptions,
} from "../src/config/profiles.js"

// ─── Built-in profiles ───

describe("BUILTIN_PROFILES", () => {
  test("log-review profile exists with patterns", () => {
    expect(BUILTIN_PROFILES["log-review"]).toBeDefined()
    expect(BUILTIN_PROFILES["log-review"].patterns.length).toBeGreaterThan(0)
    expect(BUILTIN_PROFILES["log-review"].description).toContain("log")
  })

  test("security-monitoring profile exists with patterns", () => {
    expect(BUILTIN_PROFILES["security-monitoring"]).toBeDefined()
    expect(
      BUILTIN_PROFILES["security-monitoring"].patterns.length,
    ).toBeGreaterThan(0)
    expect(BUILTIN_PROFILES["security-monitoring"].description).toContain(
      "CrowdSec",
    )
  })

  test("security-monitoring includes crowdsec-cli patterns", () => {
    const patterns = BUILTIN_PROFILES["security-monitoring"].patterns
    expect(patterns).toContain("crowdsec-cli decisions list")
    expect(patterns).toContain("crowdsec-cli metrics")
  })

  test("security-monitoring includes ufw patterns", () => {
    const patterns = BUILTIN_PROFILES["security-monitoring"].patterns
    expect(patterns).toContain("ufw status")
    expect(patterns).toContain("ufw status *")
  })

  test("log-review includes auth.log patterns", () => {
    const patterns = BUILTIN_PROFILES["log-review"].patterns
    expect(patterns).toContain("tail * /var/log/auth.log")
    expect(patterns).toContain("cat /var/log/auth.log")
    expect(patterns).toContain("head * /var/log/auth.log")
  })

  test("service-status profile exists with patterns", () => {
    expect(BUILTIN_PROFILES["service-status"]).toBeDefined()
    expect(
      BUILTIN_PROFILES["service-status"].patterns.length,
    ).toBeGreaterThan(0)
    expect(BUILTIN_PROFILES["service-status"].description).toContain(
      "systemctl",
    )
  })

  test("system-health profile exists with patterns", () => {
    expect(BUILTIN_PROFILES["system-health"]).toBeDefined()
    expect(
      BUILTIN_PROFILES["system-health"].patterns.length,
    ).toBeGreaterThan(0)
    expect(BUILTIN_PROFILES["system-health"].description).toContain("df")
  })
})

// ─── resolveAllowedPatterns ───

describe("resolveAllowedPatterns", () => {
  test("returns empty array when nothing is configured", () => {
    const result = resolveAllowedPatterns([], {})
    expect(result).toEqual([])
  })

  test("includes user-defined allowedOperations", () => {
    const result = resolveAllowedPatterns(["nginx -t", "certbot certificates"], {})
    expect(result).toContain("nginx -t")
    expect(result).toContain("certbot certificates")
  })

  test("includes patterns from enabled profile (boolean true)", () => {
    const result = resolveAllowedPatterns([], {
      "system-health": true,
    })
    expect(result.length).toBeGreaterThan(0)
    expect(result).toContain("df")
    expect(result).toContain("uptime")
  })

  test("excludes patterns from disabled profile (boolean false)", () => {
    const result = resolveAllowedPatterns([], {
      "system-health": false,
    })
    expect(result).toEqual([])
  })

  test("includes patterns from enabled profile (object form)", () => {
    const result = resolveAllowedPatterns([], {
      "log-review": { enabled: true },
    })
    expect(result.length).toBeGreaterThan(0)
    expect(result).toContain("dmesg")
  })

  test("excludes patterns from disabled profile (object form)", () => {
    const result = resolveAllowedPatterns([], {
      "log-review": { enabled: false },
    })
    expect(result).toEqual([])
  })

  test("includes additionalPatterns from profile config", () => {
    const result = resolveAllowedPatterns([], {
      "security-monitoring": {
        enabled: true,
        additionalPatterns: ["custom-tool status *"],
      },
    })
    expect(result).toContain("custom-tool status *")
    // Also includes built-in patterns
    expect(result).toContain("cscli decisions list")
  })

  test("merges user patterns and profile patterns without duplicates", () => {
    const result = resolveAllowedPatterns(["df", "custom-cmd"], {
      "system-health": true,
    })
    // df appears in both user patterns and system-health profile
    const dfCount = result.filter((p) => p === "df").length
    expect(dfCount).toBe(1)
    expect(result).toContain("custom-cmd")
    expect(result).toContain("uptime")
  })

  test("ignores unknown profile names", () => {
    const result = resolveAllowedPatterns([], {
      "nonexistent-profile": true,
    })
    expect(result).toEqual([])
  })

  test("merges multiple enabled profiles", () => {
    const result = resolveAllowedPatterns([], {
      "log-review": true,
      "system-health": true,
    })
    // Should have patterns from both profiles
    expect(result).toContain("dmesg")
    expect(result).toContain("uptime")
  })
})

// ─── getActiveProfileDescriptions ───

describe("getActiveProfileDescriptions", () => {
  test("returns empty for no profiles", () => {
    expect(getActiveProfileDescriptions({})).toEqual([])
  })

  test("returns descriptions for enabled profiles", () => {
    const result = getActiveProfileDescriptions({
      "log-review": true,
      "system-health": false,
    })
    expect(result).toHaveLength(1)
    expect(result[0].name).toBe("log-review")
    expect(result[0].description).toContain("log")
  })

  test("ignores unknown profile names", () => {
    const result = getActiveProfileDescriptions({
      "nonexistent-profile": true,
    })
    expect(result).toEqual([])
  })
})
