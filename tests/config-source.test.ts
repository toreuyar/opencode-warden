import { afterEach, describe, expect, test } from "bun:test"
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "fs"
import { tmpdir } from "os"
import { join } from "path"
import { loadConfig } from "../src/config/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"

const tempDirs: string[] = []

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  }
})

function makeProjectDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "warden-config-source-"))
  tempDirs.push(dir)
  return dir
}

function projectConfigPath(projectDir: string): string {
  return join(projectDir, ".opencode", "opencode-warden.json")
}

function writeProjectConfig(projectDir: string, config: Record<string, unknown>): string {
  const path = projectConfigPath(projectDir)
  mkdirSync(join(projectDir, ".opencode"), { recursive: true })
  writeFileSync(path, JSON.stringify(config, null, 2))
  return path
}

function withHome<T>(home: string, fn: () => T): T {
  const previous = process.env.HOME
  process.env.HOME = home
  try {
    return fn()
  } finally {
    if (previous === undefined) delete process.env.HOME
    else process.env.HOME = previous
  }
}

function writeGlobalConfig(home: string, contents: string): string {
  const path = join(home, ".config", "opencode", "opencode-warden.json")
  mkdirSync(join(home, ".config", "opencode"), { recursive: true })
  writeFileSync(path, contents)
  return path
}

describe("inline config source", () => {
  test("uses inline options over defaults when no config file exists", () => {
    const dir = makeProjectDir()

    const result = loadConfig(dir, {
      skipGlobalConfig: true,
      inlineConfig: {
        redactionEnabled: false,
        blockedTools: ["bash"],
      },
    })

    expect(result.failure).toBeNull()
    expect(result.warnings).toEqual([])
    expect(result.config.redactionEnabled).toBe(false)
    // Canonical tool vocabulary is still applied to inline config.
    expect(result.config.blockedTools).toEqual(["shell"])
    // Unspecified fields keep defaults.
    expect(result.config.blockedFilePaths).toEqual(DEFAULT_CONFIG.blockedFilePaths)
  })

  test("validates inline options with the same schema and fails closed", () => {
    const dir = makeProjectDir()

    const result = loadConfig(dir, {
      skipGlobalConfig: true,
      inlineConfig: {
        llm: {
          enabled: "yes",
          apiKey: "sk-live-SUPER-SECRET-VALUE",
        },
      },
    })

    expect(result.failure).not.toBeNull()
    expect(result.failure?.code).toBe("WARDEN_CONFIG_INVALID")
    expect(result.failure?.kind).toBe("invalid")
    expect(result.failure?.source).toBe("inline")
    expect(result.failure?.failClosed).toBe(true)
    expect(result.failure?.issues.some((issue) => issue.path === "llm.enabled")).toBe(true)

    // The failure config forces LLM evaluation on with no providers, so
    // existing LLM components fail closed instead of silently disabling
    // intended enforcement.
    expect(result.config.llm.enabled).toBe(true)
    expect(result.config.llm.safetyEvaluator.providers).toEqual([])
    expect(result.config.llm.outputSanitizer.providers).toEqual([])

    // Errors and warnings must never echo configured secret values.
    const diagnostics = [
      result.warnings.join("\n"),
      result.failure?.message ?? "",
      ...(result.failure?.issues.map((issue) => `${issue.path}: ${issue.message}`) ?? []),
    ].join("\n")
    expect(diagnostics).not.toContain("SUPER-SECRET-VALUE")
  })

  test("does not mutate the host's inline options object", () => {
    const dir = makeProjectDir()
    const inlineConfig = {
      llm: {
        enabled: true,
        baseUrl: "http://127.0.0.1:11434/v1",
        model: "test-model",
      },
    }
    const snapshot = JSON.parse(JSON.stringify(inlineConfig))

    const result = loadConfig(dir, { skipGlobalConfig: true, inlineConfig })

    expect(result.failure).toBeNull()
    expect(inlineConfig).toEqual(snapshot)
    // Inheritance/normalization happened on the validated copy only.
    expect(inlineConfig.llm).not.toHaveProperty("providers")
    expect(result.config.llm.safetyEvaluator.providers).toHaveLength(1)
    expect(result.config.llm.safetyEvaluator.providers[0].baseUrl).toBe(
      "http://127.0.0.1:11434/v1",
    )
    expect(result.config.llm.safetyEvaluator.providers[0].model).toBe("test-model")
  })

  test("strips unknown keys, matching the existing schema semantics", () => {
    const dir = makeProjectDir()

    const result = loadConfig(dir, {
      skipGlobalConfig: true,
      inlineConfig: {
        llm: {
          outputSanitizer: {
            someFutureField: -1,
          },
        },
      },
    })

    // Unknown keys are intentionally stripped (non-strict schema), while
    // known keys with invalid values are hard failures (covered above).
    expect(result.failure).toBeNull()
    expect(result.warnings).toEqual([])
  })

  test("rejects an invalid known LLM value instead of defaulting silently", () => {
    const dir = makeProjectDir()

    const result = loadConfig(dir, {
      skipGlobalConfig: true,
      inlineConfig: {
        llm: {
          enabled: true,
          baseUrl: "not-a-url",
        },
      },
    })

    expect(result.failure?.code).toBe("WARDEN_CONFIG_INVALID")
    expect(result.failure?.issues.some((issue) => issue.path === "llm.baseUrl")).toBe(true)
    expect(result.config.llm.enabled).toBe(true)
    expect(result.config.llm.safetyEvaluator.providers).toEqual([])
  })
})

describe("file source precedence", () => {
  test("project config exists: inline options are ignored entirely", () => {
    const dir = makeProjectDir()
    writeProjectConfig(dir, { notifications: false })

    const result = loadConfig(dir, {
      skipGlobalConfig: true,
      inlineConfig: { notifications: true, redactionEnabled: false },
    })

    expect(result.failure).toBeNull()
    expect(result.warnings).toEqual([])
    expect(result.config.notifications).toBe(false)
    expect(result.config.redactionEnabled).toBe(DEFAULT_CONFIG.redactionEnabled)
  })

  test("global config exists: inline options are ignored entirely", () => {
    const home = makeProjectDir()
    const dir = makeProjectDir()
    writeGlobalConfig(home, JSON.stringify({ notifications: false }))

    const result = withHome(home, () =>
      loadConfig(dir, {
        inlineConfig: { notifications: true },
      }),
    )

    expect(result.failure).toBeNull()
    expect(result.config.notifications).toBe(false)
  })

  test("skipGlobalConfig ignores an existing global config so inline can be used", () => {
    const home = makeProjectDir()
    const dir = makeProjectDir()
    writeGlobalConfig(home, JSON.stringify({ notifications: false }))

    const result = withHome(home, () =>
      loadConfig(dir, {
        skipGlobalConfig: true,
        inlineConfig: { notifications: true, redactionEnabled: false },
      }),
    )

    expect(result.failure).toBeNull()
    expect(result.config.notifications).toBe(true)
    expect(result.config.redactionEnabled).toBe(false)
  })

  test("global config is merged before project config", () => {
    const home = makeProjectDir()
    const dir = makeProjectDir()
    writeGlobalConfig(home, JSON.stringify({ notifications: false, blockedTools: ["bash"] }))
    writeProjectConfig(dir, { notifications: true })

    const result = withHome(home, () => loadConfig(dir, { inlineConfig: { notifications: false } }))

    expect(result.failure).toBeNull()
    // Project override wins.
    expect(result.config.notifications).toBe(true)
    // Global value survives when the project does not override it, and is
    // canonicalized in memory.
    expect(result.config.blockedTools).toEqual(["shell"])
    // Inline was ignored because file sources exist.
    expect(result.config.notifications).not.toBe(false)
  })

  test("arrays are replaced by a higher layer, not appended", () => {
    const dir = makeProjectDir()
    writeProjectConfig(dir, { blockedFilePaths: [".env"] })

    const result = loadConfig(dir, { skipGlobalConfig: true })

    expect(result.failure).toBeNull()
    expect(result.config.blockedFilePaths).toEqual([".env"])
  })

  test("missing file sources yield defaults", () => {
    const dir = makeProjectDir()

    const result = loadConfig(dir, { skipGlobalConfig: true })

    expect(result.failure).toBeNull()
    expect(result.warnings).toEqual([])
    expect(result.config).toEqual(DEFAULT_CONFIG)
  })
})

describe("invalid and unreadable file sources fail closed", () => {
  test("returns a failure signal instead of throwing during plugin setup", () => {
    const dir = makeProjectDir()
    mkdirSync(join(dir, ".opencode"), { recursive: true })
    writeFileSync(projectConfigPath(dir), "{ broken json")

    let result: ReturnType<typeof loadConfig> | undefined
    expect(() => {
      result = loadConfig(dir, { skipGlobalConfig: true })
    }).not.toThrow()
    expect(result?.failure?.failClosed).toBe(true)
  })

  test("invalid project config does not fall back to inline or defaults", () => {
    const dir = makeProjectDir()
    const path = projectConfigPath(dir)
    mkdirSync(join(dir, ".opencode"), { recursive: true })
    writeFileSync(path, "{ not valid json")
    const inlineConfig = { notifications: false }

    const result = loadConfig(dir, { skipGlobalConfig: true, inlineConfig })

    expect(result.failure?.code).toBe("WARDEN_CONFIG_INVALID")
    expect(result.failure?.kind).toBe("invalid")
    expect(result.failure?.source).toBe("project")
    expect(result.failure?.failClosed).toBe(true)
    // Neither inline (notifications=false) nor defaults are silently treated
    // as the user's configuration.
    expect(result.config.notifications).toBe(DEFAULT_CONFIG.notifications)
    expect(result.config.llm.enabled).toBe(true)
  })

  test("invalid global config does not fall back to a valid project layer", () => {
    const home = makeProjectDir()
    const dir = makeProjectDir()
    writeGlobalConfig(home, "{ broken json")
    writeProjectConfig(dir, { notifications: false })

    const result = withHome(home, () => loadConfig(dir))

    expect(result.failure?.source).toBe("global")
    expect(result.failure?.code).toBe("WARDEN_CONFIG_INVALID")
    expect(result.config.notifications).toBe(DEFAULT_CONFIG.notifications)
    expect(result.config.llm.enabled).toBe(true)
  })

  test("invalid project config does not fall back to a valid global layer", () => {
    const home = makeProjectDir()
    const dir = makeProjectDir()
    writeGlobalConfig(home, JSON.stringify({ notifications: false }))
    const path = projectConfigPath(dir)
    mkdirSync(join(dir, ".opencode"), { recursive: true })
    writeFileSync(path, "{ broken json")

    const result = withHome(home, () => loadConfig(dir))

    expect(result.failure?.source).toBe("project")
    expect(result.config.notifications).toBe(DEFAULT_CONFIG.notifications)
    expect(result.config.llm.enabled).toBe(true)
  })

  test("a dangling symlink is present-but-unreadable, not missing", () => {
    const dir = makeProjectDir()
    const path = projectConfigPath(dir)
    mkdirSync(join(dir, ".opencode"), { recursive: true })
    symlinkSync(join(dir, "missing-target.json"), path)

    const result = loadConfig(dir, {
      skipGlobalConfig: true,
      inlineConfig: { notifications: false },
    })

    expect(result.failure?.code).toBe("WARDEN_CONFIG_UNREADABLE")
    expect(result.failure?.kind).toBe("unreadable")
    expect(result.failure?.source).toBe("project")
    expect(result.config.notifications).toBe(DEFAULT_CONFIG.notifications)
    expect(result.config.llm.enabled).toBe(true)
  })

  test("a directory at the config path is present-but-unreadable", () => {
    const dir = makeProjectDir()
    mkdirSync(projectConfigPath(dir), { recursive: true })

    const result = loadConfig(dir, { skipGlobalConfig: true })

    expect(result.failure?.code).toBe("WARDEN_CONFIG_UNREADABLE")
    expect(result.failure?.kind).toBe("unreadable")
    expect(result.failure?.source).toBe("project")
    expect(result.config.llm.enabled).toBe(true)
  })
})
