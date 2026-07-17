import { describe, test, expect, afterEach } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"
import { isBlockedPath, isWriteProtectedPath, isPathBlockedForMode, matchGlob, extractFilePath, extractRemoteFilePathsFromArgs, extractBashFileTargets, isDynamicPathTarget } from "../src/utils/paths.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"

const tempDirs: string[] = []

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  }
})

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "warden-paths-"))
  tempDirs.push(dir)
  return dir
}

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

  test("glob-like whitelist entries do not override the blocklist", () => {
    expect(
      isBlockedPath("/project/config/.env.example", blocked, whitelisted),
    ).toBe(true)
  })

  test("exact whitelist entries override the blocklist", () => {
    expect(
      isBlockedPath("/project/config/.env.example", blocked, ["/project/config/.env.example"]),
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
  test("extracts remote paths from SSH command (read mode)", () => {
    const paths = extractRemoteFilePathsFromArgs("bash", {
      command: 'ssh user@host.com "cat /etc/passwd"',
    })
    expect(paths).toEqual([{ path: "/etc/passwd", mode: "read" }])
  })

  test("extracts remote paths from SCP download (read mode)", () => {
    const paths = extractRemoteFilePathsFromArgs("bash", {
      command: "scp user@server.com:/etc/shadow ./local/",
    })
    expect(paths).toEqual([{ path: "/etc/shadow", mode: "read" }])
  })

  test("extracts remote paths from SCP upload (write mode)", () => {
    const paths = extractRemoteFilePathsFromArgs("bash", {
      command: "scp ./local.txt user@server.com:/home/deploy/.env",
    })
    expect(paths).toEqual([{ path: "/home/deploy/.env", mode: "write" }])
  })

  test("extracts remote paths from rsync download (read) and upload (write)", () => {
    const dl = extractRemoteFilePathsFromArgs("bash", {
      command: "rsync -avz user@server.com:/home/user/.env ./local/",
    })
    expect(dl).toEqual([{ path: "/home/user/.env", mode: "read" }])
    const ul = extractRemoteFilePathsFromArgs("bash", {
      command: "rsync -avz ./local.txt user@server.com:/home/deploy/.env",
    })
    expect(ul).toEqual([{ path: "/home/deploy/.env", mode: "write" }])
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

describe("extractBashFileTargets", () => {
  test("extracts append write target from echo >> file", () => {
    const r = extractBashFileTargets("echo 'ssh-ed25519 AAAA...' >> ~/.ssh/authorized_keys")
    expect(r.writes).toEqual(["~/.ssh/authorized_keys"])
    expect(r.reads).toEqual([])
  })

  test("extracts overwrite write target from > file", () => {
    expect(extractBashFileTargets("echo data > /project/.env").writes).toEqual([
      "/project/.env",
    ])
  })

  test("extracts write target from cat /dev/null > file", () => {
    expect(
      extractBashFileTargets("cat /dev/null > /var/log/auth.log").writes,
    ).toEqual(["/var/log/auth.log"])
  })

  test("extracts fd-specific redirect write targets (1>, 2>, 1>>, 2>>)", () => {
    expect(extractBashFileTargets("cmd 1> /tmp/out.log").writes).toEqual(["/tmp/out.log"])
    expect(extractBashFileTargets("cmd 2>> /tmp/err.log").writes).toEqual(["/tmp/err.log"])
  })

  test("extracts bash &> and &>> both-stream write redirects", () => {
    expect(extractBashFileTargets("cmd &> /tmp/both.log").writes).toEqual(["/tmp/both.log"])
    expect(extractBashFileTargets("cmd &>> /tmp/both.log").writes).toEqual(["/tmp/both.log"])
  })

  test("extracts glued write redirect (no space): >file, 2>file, >>file", () => {
    expect(extractBashFileTargets("echo data>/project/.env").writes).toEqual([
      "/project/.env",
    ])
    expect(extractBashFileTargets("echo data >/project/.env").writes).toEqual([
      "/project/.env",
    ])
    expect(extractBashFileTargets("cmd 2>>/tmp/err.log").writes).toEqual([
      "/tmp/err.log",
    ])
  })

  test("extracts truncate write target", () => {
    expect(
      extractBashFileTargets("truncate -s 0 /var/log/syslog").writes,
    ).toEqual(["/var/log/syslog"])
  })

  test("truncate -s with non-numeric size does not leak the size as a target", () => {
    // -s 1M: 1M is the SIZE arg, not a file. Must be skipped, not extracted.
    expect(
      extractBashFileTargets("truncate -s 1M /var/log/syslog").writes,
    ).toEqual(["/var/log/syslog"])
    expect(
      extractBashFileTargets("truncate -s 100K /var/log/auth.log").writes,
    ).toEqual(["/var/log/auth.log"])
  })

  test("truncate -r reference file is not treated as a write target", () => {
    // -r /etc/hosts references its size (a read); only the real target is written.
    expect(
      extractBashFileTargets("truncate -r /etc/hosts /var/log/syslog").writes,
    ).toEqual(["/var/log/syslog"])
  })

  test("truncate --size/--reference long forms also skip their argument", () => {
    expect(
      extractBashFileTargets("truncate --size 2G /var/log/syslog").writes,
    ).toEqual(["/var/log/syslog"])
    expect(
      extractBashFileTargets("truncate --reference /etc/hosts /var/log/syslog")
        .writes,
    ).toEqual(["/var/log/syslog"])
  })

  test("extracts input redirect as a READ target (< file)", () => {
    const r = extractBashFileTargets("mail root < /etc/shadow")
    expect(r.reads).toEqual(["/etc/shadow"])
    expect(r.writes).toEqual([])
  })

  test("extracts glued input redirect as READ (<file)", () => {
    expect(extractBashFileTargets("cmd </etc/shadow").reads).toEqual(["/etc/shadow"])
  })

  test("detects dynamic shell path targets", () => {
    expect(isDynamicPathTarget("$HOME/.ssh/id_rsa")).toBe(true)
    expect(isDynamicPathTarget("${HOME}/.env")).toBe(true)
    expect(isDynamicPathTarget("$(pwd)/.env")).toBe(true)
    expect(isDynamicPathTarget("`pwd`/.env")).toBe(true)
    expect(isDynamicPathTarget("/tmp/static.env")).toBe(false)
  })

  test("extracts tee write target", () => {
    expect(extractBashFileTargets("echo data | tee /etc/sudoers").writes).toEqual([
      "/etc/sudoers",
    ])
  })

  test("extracts tee -a write target", () => {
    expect(
      extractBashFileTargets("echo data | tee -a ~/.ssh/authorized_keys").writes,
    ).toEqual(["~/.ssh/authorized_keys"])
  })

  test("extracts multiple tee write targets", () => {
    expect(
      extractBashFileTargets("echo data | tee /tmp/a.log /tmp/b.log").writes,
    ).toEqual(["/tmp/a.log", "/tmp/b.log"])
  })

  test("tee stops at pipe separator", () => {
    const r = extractBashFileTargets("echo x | tee /tmp/a.log | grep y")
    expect(r.writes).toEqual(["/tmp/a.log"])
  })

  test("extracts dd of= write target", () => {
    expect(
      extractBashFileTargets("dd if=/dev/zero of=/etc/sudoers bs=1M count=1").writes,
    ).toEqual(["/etc/sudoers"])
  })

  test("skips fd-duplication (2>&1, 1>&2)", () => {
    expect(extractBashFileTargets("cmd 2>&1").writes).toEqual([])
    expect(extractBashFileTargets("cmd 1>&2").writes).toEqual([])
  })

  test("skips fd-close (>&-)", () => {
    expect(extractBashFileTargets("cmd 2>&-").writes).toEqual([])
  })

  test("skips /dev/null as a target", () => {
    expect(extractBashFileTargets("cmd > /dev/null 2>&1").writes).toEqual([])
  })

  test("skips heredoc markers (<<)", () => {
    expect(extractBashFileTargets("cat << EOF").writes).toEqual([])
    expect(extractBashFileTargets("cat <<EOF").writes).toEqual([])
  })

  test("handles quoted target paths", () => {
    expect(
      extractBashFileTargets('echo x >> "~/.ssh/authorized_keys"').writes,
    ).toEqual(["~/.ssh/authorized_keys"])
    expect(
      extractBashFileTargets("echo x > '/project/.env'").writes,
    ).toEqual(["/project/.env"])
  })

  test("returns empty for command with no redirections", () => {
    const r1 = extractBashFileTargets("ls -la /tmp")
    expect(r1.writes).toEqual([])
    expect(r1.reads).toEqual([])
    const r2 = extractBashFileTargets("git status")
    expect(r2.writes).toEqual([])
  })

  test("returns empty for empty/whitespace command", () => {
    expect(extractBashFileTargets("")).toEqual({ reads: [], writes: [] })
    expect(extractBashFileTargets("   ")).toEqual({ reads: [], writes: [] })
  })

  test("does not treat > inside a quoted string as a redirect", () => {
    const r = extractBashFileTargets('grep "a>b" file.txt')
    expect(r.writes).toEqual([])
  })

  test("integration: write targets match the default blocklist", () => {
    const blocked = DEFAULT_CONFIG.blockedFilePaths
    expect(
      extractBashFileTargets("echo 'ssh-ed25519 AAAA...' >> ~/.ssh/authorized_keys")
        .writes.some((p) => isBlockedPath(p, blocked, [])),
    ).toBe(true)
    expect(
      extractBashFileTargets("echo SECRET=x > /app/.env").writes.some((p) =>
        isBlockedPath(p, blocked, []),
      ),
    ).toBe(true)
  })
})

describe("isWriteProtectedPath", () => {
  const wp = ["**/var/log/**"]
  const wl: string[] = []

  test("matches a write-protected log path", () => {
    expect(isWriteProtectedPath("/var/log/syslog", wp, wl)).toBe(true)
    expect(isWriteProtectedPath("/var/log/nginx/access.log", wp, wl)).toBe(true)
  })

  test("does not match a non-protected path", () => {
    expect(isWriteProtectedPath("/etc/passwd", wp, wl)).toBe(false)
    expect(isWriteProtectedPath("/tmp/output.txt", wp, wl)).toBe(false)
  })

  test("exact whitelist overrides write-protection", () => {
    expect(
      isWriteProtectedPath("/var/log/syslog", wp, ["/var/log/syslog"]),
    ).toBe(false)
  })
})

describe("isPathBlockedForMode", () => {
  const blocked = DEFAULT_CONFIG.blockedFilePaths
  const wp = DEFAULT_CONFIG.writeProtectedPaths
  const wl: string[] = []

  test("read of a blocked (secret) file is blocked", () => {
    expect(isPathBlockedForMode("/app/.env", "read", blocked, wp, wl)).toBe(true)
  })

  test("write of a blocked (secret) file is blocked", () => {
    expect(isPathBlockedForMode("/app/.env", "write", blocked, wp, wl)).toBe(true)
  })

  test("read of a write-protected log is ALLOWED", () => {
    expect(isPathBlockedForMode("/var/log/syslog", "read", blocked, wp, wl)).toBe(false)
  })

  test("write of a write-protected log is blocked", () => {
    expect(isPathBlockedForMode("/var/log/syslog", "write", blocked, wp, wl)).toBe(true)
  })

  test("truncate target on a write-protected log is blocked for write", () => {
    expect(isPathBlockedForMode("/var/log/auth.log", "write", blocked, wp, wl)).toBe(true)
  })

  test("ordinary file is allowed for both modes", () => {
    expect(isPathBlockedForMode("/project/src/index.ts", "read", blocked, wp, wl)).toBe(false)
    expect(isPathBlockedForMode("/project/src/index.ts", "write", blocked, wp, wl)).toBe(false)
  })

  test("exact whitelist overrides both modes", () => {
    expect(
      isPathBlockedForMode("/app/.env", "write", blocked, wp, ["/app/.env"]),
    ).toBe(false)
  })

  test("existing symlink target is checked through its canonical path", () => {
    const root = makeTempDir()
    const secretDir = join(root, "secret")
    const publicDir = join(root, "public")
    mkdirSync(secretDir)
    mkdirSync(publicDir)
    const secretPath = join(secretDir, ".env")
    const linkPath = join(publicDir, "link")
    writeFileSync(secretPath, "TOKEN=value")
    symlinkSync(secretPath, linkPath)

    expect(
      isPathBlockedForMode(linkPath, "read", ["**/.env"], [], [], root),
    ).toBe(true)
  })

  test("write checks resolve through the nearest existing symlink parent", () => {
    const root = makeTempDir()
    const secretDir = join(root, "secret")
    const publicDir = join(root, "public")
    mkdirSync(secretDir)
    mkdirSync(publicDir)
    const linkDir = join(publicDir, "linked")
    symlinkSync(secretDir, linkDir, "dir")

    expect(
      isPathBlockedForMode(join(linkDir, ".env"), "write", ["**/.env"], [], [], root),
    ).toBe(true)
  })
})
