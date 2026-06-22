import { describe, test, expect } from "bun:test"
import { getPolicyLogPath, loadPolicyLog, savePolicyLog } from "../src/utils/policy-log.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import type { SecurityGuardConfig } from "../src/types.js"
import { existsSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "fs"
import { join, dirname } from "path"

describe("Policy Log Persistence", () => {
  test("loadPolicyLog returns empty Set when file does not exist", () => {
    const config = DEFAULT_CONFIG
    const projectDir = "/tmp/warden-test-nonexistent-" + Date.now()
    const result = loadPolicyLog(config, projectDir)
    expect(result).toEqual(new Set())
  })

  test("loadPolicyLog loads session IDs from valid file", () => {
    const config = DEFAULT_CONFIG
    const projectDir = "/tmp/warden-test-load-" + Date.now()
    const logPath = getPolicyLogPath(config, projectDir)
    mkdirSync(dirname(logPath), { recursive: true })
    writeFileSync(logPath, JSON.stringify({ sessionIds: ["session-1", "session-2"] }, null, 2))
    
    const result = loadPolicyLog(config, projectDir)
    expect(result).toEqual(new Set(["session-1", "session-2"]))
    
    rmSync(projectDir, { recursive: true, force: true })
  })

  test("loadPolicyLog handles corrupt JSON gracefully", () => {
    const config = DEFAULT_CONFIG
    const projectDir = "/tmp/warden-test-corrupt-" + Date.now()
    const logPath = getPolicyLogPath(config, projectDir)
    mkdirSync(dirname(logPath), { recursive: true })
    writeFileSync(logPath, "not valid json")
    
    const result = loadPolicyLog(config, projectDir)
    expect(result).toEqual(new Set())
    
    rmSync(projectDir, { recursive: true, force: true })
  })

  test("savePolicyLog creates directory and writes file", () => {
    const config = DEFAULT_CONFIG
    const projectDir = "/tmp/warden-test-save-" + Date.now()
    const policyInjected = new Set(["session-a", "session-b"])
    
    savePolicyLog(config, projectDir, policyInjected)
    
    const logPath = getPolicyLogPath(config, projectDir)
    expect(existsSync(logPath)).toBe(true)
    
    const data = JSON.parse(readFileSync(logPath, "utf-8"))
    expect(data.sessionIds).toEqual(["session-a", "session-b"])
    
    rmSync(projectDir, { recursive: true, force: true })
  })

  test("savePolicyLog updates existing file", () => {
    const config = DEFAULT_CONFIG
    const projectDir = "/tmp/warden-test-update-" + Date.now()
    const logPath = getPolicyLogPath(config, projectDir)
    mkdirSync(dirname(logPath), { recursive: true })
    writeFileSync(logPath, JSON.stringify({ sessionIds: ["old-session"] }, null, 2))
    
    const policyInjected = new Set(["new-session"])
    savePolicyLog(config, projectDir, policyInjected)
    
    const data = JSON.parse(readFileSync(logPath, "utf-8"))
    expect(data.sessionIds).toEqual(["new-session"])
    
    rmSync(projectDir, { recursive: true, force: true })
  })

  test("getPolicyLogPath handles absolute paths", () => {
    const config = {
      ...DEFAULT_CONFIG,
      policy: { filePath: "/absolute/path/policy.log.json" },
    } as SecurityGuardConfig
    const result = getPolicyLogPath(config, "/project")
    expect(result).toBe("/absolute/path/policy.log.json")
  })

  test("getPolicyLogPath handles relative paths", () => {
    const config = DEFAULT_CONFIG
    const result = getPolicyLogPath(config, "/project")
    expect(result).toBe("/project/.opencode/warden/policy.log.json")
  })
})