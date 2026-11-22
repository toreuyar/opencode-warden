import { describe, expect, test } from "bun:test"
import { hasSequentialShellBatch } from "../src/utils/shell-sequence.js"

describe("static shell sequence policy", () => {
  test.each([
    "git status; git diff",
    "git status # comment; not another operation\n\n# another comment\ngit diff",
    "git diff | wc -l; git status",
    "git diff |& wc -l\ngit status",
    "cat <<'EOF'\none; two\nEOF\ngit status",
    "cd src; git status",
    "printf '%s' 'é'; git status",
  ])("blocks separate root operations in %j", (command) => {
    expect(hasSequentialShellBatch("shell", command)).toBe(true)
    expect(hasSequentialShellBatch("bash", command)).toBe(true)
  })

  test.each([
    "git status;",
    "git status\n# git diff\n",
    "git status # ; git diff",
    "git status &&\ngit diff",
    "git status ||\ngit diff",
    "git diff |\nwc -l",
    "git diff |&\nwc -l",
    "git status &\ngit diff",
    "git status; git diff &",
    "MODE=test; printf '%s' \"$MODE\"",
    "git \\\nstatus",
    "printf '%s' 'one;\ntwo'",
    "printf '%s' \"one;\ntwo\"",
    "printf '%s' one\\;two",
    "cat <<'EOF'\ngit status; git diff\nEOF\n",
    "<<'EOF'\ngit status; git diff\nEOF\n",
    "printf '%s' \"$(echo one; echo two)\"",
    "if true; then git status; fi",
    "git status; '",
  ])("does not classify %j as a batch", (command) => {
    expect(hasSequentialShellBatch("shell", command)).toBe(false)
  })

  test("only inspects shell command strings", () => {
    expect(hasSequentialShellBatch("write", "git status; git diff")).toBe(false)
    expect(hasSequentialShellBatch("shell", null)).toBe(false)
  })
})
