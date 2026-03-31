import { describe, test, expect } from "bun:test"
import { deepScan } from "../src/utils/deep-scan.js"
import { createDetectionEngine } from "../src/detection/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"

describe("Deep Scan", () => {
  const engine = createDetectionEngine(DEFAULT_CONFIG)

  test("scans simple string value", () => {
    const result = deepScan(
      "My key is sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      engine,
    )
    expect(result.totalMatches).toBeGreaterThan(0)
    expect(result.value as string).not.toContain("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
  })

  test("scans nested object", () => {
    const obj = {
      config: {
        apiKey: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        name: "safe value",
      },
      list: ["ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"],
    }
    const result = deepScan(obj, engine)
    expect(result.totalMatches).toBeGreaterThan(0)

    const scanned = result.value as Record<string, unknown>
    const config = scanned.config as Record<string, string>
    expect(config.apiKey).not.toContain("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    expect(config.name).toBe("safe value")

    const list = scanned.list as string[]
    expect(list[0]).not.toContain("ABCDEFGHIJKLMNOPQRST")
  })

  test("handles arrays", () => {
    const arr = [
      "safe",
      "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "also safe",
    ]
    const result = deepScan(arr, engine)
    expect(result.totalMatches).toBeGreaterThan(0)
    const scanned = result.value as string[]
    expect(scanned[0]).toBe("safe")
    expect(scanned[1]).not.toContain("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    expect(scanned[2]).toBe("also safe")
  })

  test("handles primitives", () => {
    expect(deepScan(42, engine).totalMatches).toBe(0)
    expect(deepScan(true, engine).totalMatches).toBe(0)
    expect(deepScan(null, engine).totalMatches).toBe(0)
    expect(deepScan(undefined, engine).totalMatches).toBe(0)
  })

  test("handles empty object", () => {
    const result = deepScan({}, engine)
    expect(result.totalMatches).toBe(0)
    expect(result.value).toEqual({})
  })

  test("handles deeply nested objects (respects max depth)", () => {
    let obj: Record<string, unknown> = { key: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
    for (let i = 0; i < 15; i++) {
      obj = { nested: obj }
    }
    // Should not throw, even if it can't scan beyond depth 10
    const result = deepScan(obj, engine)
    expect(result).toBeDefined()
  })
})
