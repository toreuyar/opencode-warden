import { describe, test, expect } from "bun:test"
import {
  canonicalToolName,
  extractPathArgument,
  isToolInList,
  normalizeToolList,
  toolNameAliases,
  toolNamesMatch,
} from "../src/utils/tool-compat.js"

describe("tool name canonicalization", () => {
  test("maps V1 shell/task names to V2 canonical names", () => {
    expect(canonicalToolName("bash")).toBe("shell")
    expect(canonicalToolName("task")).toBe("subagent")
  })

  test("keeps canonical and unknown tool names unchanged", () => {
    expect(canonicalToolName("shell")).toBe("shell")
    expect(canonicalToolName("subagent")).toBe("subagent")
    expect(canonicalToolName("read")).toBe("read")
    expect(canonicalToolName("custom.tool")).toBe("custom.tool")
  })

  test("returns canonical-first aliases for equivalent tools", () => {
    expect(toolNameAliases("bash")).toEqual(["shell", "bash"])
    expect(toolNameAliases("shell")).toEqual(["shell", "bash"])
    expect(toolNameAliases("task")).toEqual(["subagent", "task"])
    expect(toolNameAliases("subagent")).toEqual(["subagent", "task"])
    expect(toolNameAliases("read")).toEqual(["read"])
  })

  test("matches equivalent names and rejects unrelated names", () => {
    expect(toolNamesMatch("bash", "shell")).toBe(true)
    expect(toolNamesMatch("task", "subagent")).toBe(true)
    expect(toolNamesMatch("read", "write")).toBe(false)
    expect(toolNamesMatch("shell", "read")).toBe(false)
  })

  test("checks runtime names against configured lists", () => {
    expect(isToolInList("shell", ["bash", "write"])).toBe(true)
    expect(isToolInList("bash", ["shell", "write"])).toBe(true)
    expect(isToolInList("subagent", ["task"])).toBe(true)
    expect(isToolInList("task", ["subagent"])).toBe(true)
    expect(isToolInList("shell", ["read", "grep"])).toBe(false)
  })
})

describe("tool list normalization", () => {
  test("canonicalizes aliases, preserves order, and deduplicates", () => {
    expect(normalizeToolList(["bash", "read", "task", "shell", "subagent", "write"])).toEqual([
      "shell",
      "read",
      "subagent",
      "write",
    ])
  })

  test("preserves unknown tool names and trims entries", () => {
    expect(normalizeToolList(["  my-tool  ", "bash", ""])).toEqual(["my-tool", "shell"])
    expect(normalizeToolList([])).toEqual([])
  })

  test("does not mutate the input array", () => {
    const input = ["bash", "task"]
    normalizeToolList(input)
    expect(input).toEqual(["bash", "task"])
  })
})

describe("argument path extraction", () => {
  test("prefers V2 path", () => {
    expect(extractPathArgument({ path: "/v2/file.ts", filePath: "/v1/file.ts" })).toBe(
      "/v2/file.ts",
    )
  })

  test("falls back to legacy filePath", () => {
    expect(extractPathArgument({ filePath: "/v1/file.ts" })).toBe("/v1/file.ts")
    expect(extractPathArgument({ path: "", filePath: "/v1/file.ts" })).toBe("/v1/file.ts")
  })

  test("returns undefined for missing or non-string values", () => {
    expect(extractPathArgument({})).toBeUndefined()
    expect(extractPathArgument({ path: 42, filePath: null })).toBeUndefined()
  })
})
