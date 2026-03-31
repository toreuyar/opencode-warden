import { describe, test, expect } from "bun:test"
import {
  extractExecutedFilePaths,
  isSystemPath,
  hasExecutableExtension,
  isBinaryFile,
  readFileContent,
} from "../src/utils/script-detection.js"
import { writeFileSync, mkdirSync, rmSync } from "fs"
import { join } from "path"

const INTERPRETERS = ["bash", "sh", "zsh", "python", "python3", "node", "perl", "ruby"]

describe("extractExecutedFilePaths", () => {
  test("detects direct execution with ./", () => {
    const paths = extractExecutedFilePaths("./script.sh", INTERPRETERS)
    expect(paths.length).toBe(1)
    expect(paths[0]).toContain("script.sh")
  })

  test("detects direct execution with absolute path", () => {
    const paths = extractExecutedFilePaths("/tmp/deploy.sh", INTERPRETERS)
    expect(paths).toEqual(["/tmp/deploy.sh"])
  })

  test("detects interpreter invocation", () => {
    const paths = extractExecutedFilePaths("bash /tmp/setup.sh", INTERPRETERS)
    expect(paths).toEqual(["/tmp/setup.sh"])
  })

  test("detects python interpreter invocation", () => {
    const paths = extractExecutedFilePaths("python3 /tmp/exploit.py", INTERPRETERS)
    expect(paths).toEqual(["/tmp/exploit.py"])
  })

  test("skips -c flag (inline script)", () => {
    const paths = extractExecutedFilePaths("bash -c 'echo hello'", INTERPRETERS)
    expect(paths).toHaveLength(0)
  })

  test("detects source command", () => {
    const paths = extractExecutedFilePaths("source /tmp/env.sh", INTERPRETERS)
    expect(paths).toEqual(["/tmp/env.sh"])
  })

  test("detects dot-source command", () => {
    const paths = extractExecutedFilePaths(". /tmp/env.sh", INTERPRETERS)
    expect(paths).toEqual(["/tmp/env.sh"])
  })

  test("detects chained commands (&&)", () => {
    const paths = extractExecutedFilePaths("chmod +x /tmp/a.sh && /tmp/a.sh", INTERPRETERS)
    expect(paths).toContain("/tmp/a.sh")
  })

  test("detects pipe-to-shell pattern", () => {
    const paths = extractExecutedFilePaths("cat /tmp/script.sh | bash", INTERPRETERS)
    expect(paths.some(p => p.includes("script.sh"))).toBe(true)
  })

  test("deduplicates paths", () => {
    const paths = extractExecutedFilePaths("/tmp/a.sh && /tmp/a.sh", INTERPRETERS)
    expect(paths).toEqual(["/tmp/a.sh"])
  })

  test("handles quoted paths", () => {
    const paths = extractExecutedFilePaths('bash "/tmp/my script.sh"', INTERPRETERS)
    expect(paths.some(p => p.includes("my script.sh"))).toBe(true)
  })

  test("returns empty for non-file commands", () => {
    const paths = extractExecutedFilePaths("ls -la", INTERPRETERS)
    expect(paths).toHaveLength(0)
  })

  test("handles ~ in paths", () => {
    const paths = extractExecutedFilePaths("~/script.sh", INTERPRETERS)
    expect(paths.length).toBe(1)
    // Should resolve ~ to home directory
    expect(paths[0]).not.toContain("~")
  })

  test("handles semicolon-chained commands", () => {
    const paths = extractExecutedFilePaths("/tmp/a.sh ; /tmp/b.sh", INTERPRETERS)
    expect(paths).toContain("/tmp/a.sh")
    expect(paths).toContain("/tmp/b.sh")
  })
})

describe("isSystemPath", () => {
  const systemPaths = ["/usr/bin/", "/usr/local/bin/", "/bin/", "/sbin/"]

  test("returns true for system paths", () => {
    expect(isSystemPath("/usr/bin/python3", systemPaths)).toBe(true)
    expect(isSystemPath("/bin/bash", systemPaths)).toBe(true)
    expect(isSystemPath("/usr/local/bin/node", systemPaths)).toBe(true)
  })

  test("returns false for non-system paths", () => {
    expect(isSystemPath("/tmp/script.sh", systemPaths)).toBe(false)
    expect(isSystemPath("/home/user/script.sh", systemPaths)).toBe(false)
    expect(isSystemPath("./script.sh", systemPaths)).toBe(false)
  })
})

describe("hasExecutableExtension", () => {
  const extensions = [".sh", ".bash", ".py", ".js", ".rb", ".pl"]

  test("returns true for executable extensions", () => {
    expect(hasExecutableExtension("script.sh", extensions)).toBe(true)
    expect(hasExecutableExtension("/tmp/deploy.py", extensions)).toBe(true)
    expect(hasExecutableExtension("server.js", extensions)).toBe(true)
  })

  test("returns false for non-executable extensions", () => {
    expect(hasExecutableExtension("readme.md", extensions)).toBe(false)
    expect(hasExecutableExtension("config.json", extensions)).toBe(false)
    expect(hasExecutableExtension("data.txt", extensions)).toBe(false)
  })

  test("returns false for no extension", () => {
    expect(hasExecutableExtension("Makefile", extensions)).toBe(false)
  })

  test("is case-insensitive", () => {
    expect(hasExecutableExtension("SCRIPT.SH", extensions)).toBe(true)
    expect(hasExecutableExtension("deploy.PY", extensions)).toBe(true)
  })
})

describe("isBinaryFile", () => {
  const tmpDir = join(process.cwd(), ".test-tmp-binary")

  test("returns false for non-existent file", () => {
    expect(isBinaryFile("/non/existent/file")).toBe(false)
  })

  test("returns false for shebang script", () => {
    mkdirSync(tmpDir, { recursive: true })
    const file = join(tmpDir, "script.sh")
    writeFileSync(file, "#!/bin/bash\necho hello\n")
    expect(isBinaryFile(file)).toBe(false)
    rmSync(tmpDir, { recursive: true, force: true })
  })

  test("returns true for ELF binary header", () => {
    mkdirSync(tmpDir, { recursive: true })
    const file = join(tmpDir, "binary")
    const buf = Buffer.alloc(512)
    buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46 // ELF magic
    writeFileSync(file, buf)
    expect(isBinaryFile(file)).toBe(true)
    rmSync(tmpDir, { recursive: true, force: true })
  })

  test("returns true for file with many null bytes", () => {
    mkdirSync(tmpDir, { recursive: true })
    const file = join(tmpDir, "nullfile")
    const buf = Buffer.alloc(512, 0) // all nulls
    writeFileSync(file, buf)
    expect(isBinaryFile(file)).toBe(true)
    rmSync(tmpDir, { recursive: true, force: true })
  })

  test("returns false for plain text file", () => {
    mkdirSync(tmpDir, { recursive: true })
    const file = join(tmpDir, "text.txt")
    writeFileSync(file, "Hello world, this is a normal text file with no binary content.")
    expect(isBinaryFile(file)).toBe(false)
    rmSync(tmpDir, { recursive: true, force: true })
  })
})

describe("readFileContent", () => {
  const tmpDir = join(process.cwd(), ".test-tmp-readcontent")

  test("returns null for non-existent file", () => {
    expect(readFileContent("/non/existent/file", 1024)).toBeNull()
  })

  test("reads full file when under maxSize", () => {
    mkdirSync(tmpDir, { recursive: true })
    const file = join(tmpDir, "small.txt")
    writeFileSync(file, "short content")
    const result = readFileContent(file, 1024)
    expect(result).not.toBeNull()
    expect(result!.content).toBe("short content")
    expect(result!.truncated).toBe(false)
    rmSync(tmpDir, { recursive: true, force: true })
  })

  test("truncates file when over maxSize", () => {
    mkdirSync(tmpDir, { recursive: true })
    const file = join(tmpDir, "large.txt")
    writeFileSync(file, "A".repeat(1000))
    const result = readFileContent(file, 100)
    expect(result).not.toBeNull()
    expect(result!.content.length).toBe(100)
    expect(result!.truncated).toBe(true)
    rmSync(tmpDir, { recursive: true, force: true })
  })
})
