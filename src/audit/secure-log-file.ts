import { appendFileSync, chmodSync, closeSync, existsSync, lstatSync, mkdirSync, openSync, statSync } from "fs"
import { dirname } from "path"

export function ensureSecureLogTarget(filePath: string): void {
  const dir = dirname(filePath)

  if (existsSync(dir)) {
    if (lstatSync(dir).isSymbolicLink()) {
      throw new Error(`Refusing to write log under symlink directory: ${dir}`)
    }
  } else {
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    chmodSync(dir, 0o700)
  }

  if (existsSync(filePath)) {
    if (lstatSync(filePath).isSymbolicLink()) {
      throw new Error(`Refusing to write log to symlink target: ${filePath}`)
    }
    const stat = statSync(filePath)
    if (!stat.isFile()) {
      throw new Error(`Refusing to write log to non-file target: ${filePath}`)
    }
    chmodSync(filePath, 0o600)
    return
  }

  const fd = openSync(filePath, "a", 0o600)
  closeSync(fd)
  chmodSync(filePath, 0o600)
}

export function secureAppendFileSync(filePath: string, data: string): void {
  ensureSecureLogTarget(filePath)
  appendFileSync(filePath, data, { encoding: "utf-8", mode: 0o600 })
  chmodSync(filePath, 0o600)
}
