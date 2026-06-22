import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs"
import { join, dirname } from "path"
import type { SecurityGuardConfig } from "../types.js"

export function getPolicyLogPath(config: SecurityGuardConfig, projectDir: string): string {
  const fp = config.policy?.filePath || ".opencode/warden/policy.log.json"
  return fp.startsWith("/") ? fp : join(projectDir, fp)
}

export function loadPolicyLog(config: SecurityGuardConfig, projectDir: string): Set<string> {
  const path = getPolicyLogPath(config, projectDir)
  if (!existsSync(path)) return new Set()
  try {
    const data = JSON.parse(readFileSync(path, "utf-8"))
    return new Set(data.sessionIds || [])
  } catch { return new Set() }
}

export function savePolicyLog(config: SecurityGuardConfig, projectDir: string, set: Set<string>): void {
  const path = getPolicyLogPath(config, projectDir)
  const dir = dirname(path)
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  writeFileSync(path, JSON.stringify({ sessionIds: [...set] }, null, 2))
}