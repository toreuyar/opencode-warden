import { describe, test, expect, afterEach } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"
import { loadConfig } from "../src/config/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import { normalizeToolList } from "../src/utils/tool-compat.js"

const tempDirs: string[] = []

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  }
})

function makeProject(config: Record<string, unknown>): { dir: string; configPath: string } {
  const dir = mkdtempSync(join(tmpdir(), "warden-config-compat-"))
  tempDirs.push(dir)
  const configDir = join(dir, ".opencode")
  mkdirSync(configDir, { recursive: true })
  const configPath = join(configDir, "opencode-warden.json")
  writeFileSync(configPath, JSON.stringify(config, null, 2))
  return { dir, configPath }
}

describe("default tool lists reflect the V2 tool surface", () => {
  test("excludedTools no longer contains the obsolete list tool", () => {
    expect(DEFAULT_CONFIG.excludedTools).toEqual([])
    expect(DEFAULT_CONFIG.excludedTools).not.toContain("list")
  })

  test("safety and output lists normalize to canonical V2 names", () => {
    const safety = normalizeToolList(DEFAULT_CONFIG.llm.safetyEvaluator.tools)
    expect(safety).toContain("shell")
    expect(safety).toContain("patch")
    expect(safety).not.toContain("bash")

    const output = normalizeToolList(DEFAULT_CONFIG.llm.outputSanitizer.tools)
    expect(output).toContain("shell")
    expect(output).not.toContain("bash")
  })

  test("default top-level lists are already normalized", () => {
    expect(normalizeToolList(DEFAULT_CONFIG.excludedTools)).toEqual(DEFAULT_CONFIG.excludedTools)
    expect(normalizeToolList(DEFAULT_CONFIG.blockedTools)).toEqual(DEFAULT_CONFIG.blockedTools)
  })
})

describe("loadConfig normalizes configured tool lists in memory", () => {
  test("legacy configured names are canonicalized and deduplicated", () => {
    const { dir } = makeProject({
      excludedTools: ["bash", "task", "list"],
      blockedTools: ["task", "bash"],
      llm: {
        safetyEvaluator: { tools: ["bash", "task", "write", "shell"] },
        outputSanitizer: { tools: ["bash", "read", "shell"] },
      },
    })

    const { config, warnings } = loadConfig(dir, { skipGlobalConfig: true })
    expect(warnings).toHaveLength(0)

    expect(config.excludedTools).toEqual(["shell", "subagent", "list"])
    expect(config.blockedTools).toEqual(["subagent", "shell"])
    expect(config.llm.safetyEvaluator.tools).toEqual(["shell", "subagent", "write"])
    expect(config.llm.outputSanitizer.tools).toEqual(["shell", "read"])
  })

  test("custom tool names are preserved", () => {
    const { dir } = makeProject({
      blockedTools: ["my-custom-tool", "bash"],
    })

    const { config } = loadConfig(dir, { skipGlobalConfig: true })
    expect(config.blockedTools).toEqual(["my-custom-tool", "shell"])
  })

  test("does not rewrite the user's config file", () => {
    const original = {
      blockedTools: ["bash", "task"],
      llm: {
        safetyEvaluator: { tools: ["bash"] },
      },
    }
    const { dir, configPath } = makeProject(original)

    const { config } = loadConfig(dir, { skipGlobalConfig: true })
    expect(config.blockedTools).toEqual(["shell", "subagent"])

    const onDisk = JSON.parse(readFileSync(configPath, "utf-8"))
    expect(onDisk).toEqual(original)
  })
})
