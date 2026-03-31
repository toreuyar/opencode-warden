import { describe, test, expect } from "bun:test"
import { isBlockedPath, matchGlob, extractFilePath, extractRemoteFilePathsFromArgs } from "../src/utils/paths.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"

describe("Path Detection", () => {
  const blocked = DEFAULT_CONFIG.blockedFilePaths
  const whitelisted = ["**/config/.env.example"]

  test("blocks .env file", () => {
    expect(isBlockedPath("/project/.env", blocked, whitelisted)).toBe(true)
  })

  test("blocks .env.local file", () => {
    expect(isBlockedPath("/project/.env.local", blocked, whitelisted)).toBe(true)
  })

  test("blocks .env.production file", () => {
    expect(isBlockedPath("/project/.env.production", blocked, whitelisted)).toBe(true)
  })

  test("blocks .pem file", () => {
    expect(isBlockedPath("/project/certs/server.pem", blocked, whitelisted)).toBe(true)
  })

  test("blocks .key file", () => {
    expect(isBlockedPath("/project/ssl/private.key", blocked, whitelisted)).toBe(true)
  })

  test("blocks id_rsa", () => {
    expect(isBlockedPath("/home/user/.ssh/id_rsa", blocked, whitelisted)).toBe(true)
  })

  test("blocks AWS credentials", () => {
    expect(isBlockedPath("/home/user/.aws/credentials", blocked, whitelisted)).toBe(true)
  })

  test("blocks Docker config", () => {
    expect(isBlockedPath("/home/user/.docker/config.json", blocked, whitelisted)).toBe(true)
  })

  test("blocks Kube config", () => {
    expect(isBlockedPath("/home/user/.kube/config", blocked, whitelisted)).toBe(true)
  })

  test("blocks .tfstate", () => {
    expect(isBlockedPath("/project/terraform/main.tfstate", blocked, whitelisted)).toBe(true)
  })

  test("blocks .tfvars", () => {
    expect(isBlockedPath("/project/terraform/prod.tfvars", blocked, whitelisted)).toBe(true)
  })

  test("blocks .vault-token", () => {
    expect(isBlockedPath("/home/user/.vault-token", blocked, whitelisted)).toBe(true)
  })

  test("allows normal source files", () => {
    expect(isBlockedPath("/project/src/index.ts", blocked, whitelisted)).toBe(false)
  })

  test("allows package.json", () => {
    expect(isBlockedPath("/project/package.json", blocked, whitelisted)).toBe(false)
  })

  test("whitelist overrides blocklist", () => {
    expect(
      isBlockedPath("/project/config/.env.example", blocked, whitelisted),
    ).toBe(false)
  })
})

describe("Glob Matching", () => {
  test("matches **/.env", () => {
    expect(matchGlob("/project/.env", "**/.env")).toBe(true)
    expect(matchGlob("/a/b/c/.env", "**/.env")).toBe(true)
  })

  test("matches **/*.pem", () => {
    expect(matchGlob("/project/cert.pem", "**/*.pem")).toBe(true)
    expect(matchGlob("/project/ssl/cert.pem", "**/*.pem")).toBe(true)
  })

  test("doesn't match unrelated files", () => {
    expect(matchGlob("/project/src/main.ts", "**/.env")).toBe(false)
    expect(matchGlob("/project/readme.md", "**/*.pem")).toBe(false)
  })
})

describe("File Path Extraction", () => {
  test("extracts path from read tool", () => {
    expect(extractFilePath("read", { filePath: "/project/.env" })).toBe(
      "/project/.env",
    )
  })

  test("extracts path from write tool", () => {
    expect(extractFilePath("write", { filePath: "/project/out.txt" })).toBe(
      "/project/out.txt",
    )
  })

  test("extracts path from bash cat command", () => {
    expect(extractFilePath("bash", { command: "cat /etc/passwd" })).toBe(
      "/etc/passwd",
    )
  })

  test("extracts path from glob tool", () => {
    expect(extractFilePath("glob", { path: ".opencode/agents", pattern: "*" })).toBe(
      ".opencode/agents",
    )
  })

  test("returns undefined for glob without path", () => {
    expect(extractFilePath("glob", { pattern: "**/*" })).toBeUndefined()
  })

  test("returns undefined for unrecognized tool", () => {
    expect(extractFilePath("grep", { query: "test" })).toBeUndefined()
  })

  test("extracts SSH identity file path", () => {
    expect(
      extractFilePath("bash", {
        command: 'ssh -i ~/.ssh/id_rsa user@host.com "ls"',
      }),
    ).toBe("~/.ssh/id_rsa")
  })
})

describe("Remote File Path Extraction", () => {
  test("extracts remote paths from SSH command", () => {
    const paths = extractRemoteFilePathsFromArgs("bash", {
      command: 'ssh user@host.com "cat /etc/passwd"',
    })
    expect(paths).toEqual(["/etc/passwd"])
  })

  test("extracts remote paths from SCP command", () => {
    const paths = extractRemoteFilePathsFromArgs("bash", {
      command: "scp user@server.com:/etc/shadow ./local/",
    })
    expect(paths).toEqual(["/etc/shadow"])
  })

  test("returns empty for non-SSH commands", () => {
    const paths = extractRemoteFilePathsFromArgs("bash", {
      command: "ls -la /tmp",
    })
    expect(paths).toEqual([])
  })

  test("returns empty for non-bash tools", () => {
    const paths = extractRemoteFilePathsFromArgs("read", {
      filePath: "/etc/passwd",
    })
    expect(paths).toEqual([])
  })
})
