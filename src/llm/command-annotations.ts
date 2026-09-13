// ─── Command semantics annotations ───────────────────────────────────────────
// Deterministic annotations for tool families whose semantics the LLM
// demonstrably grinds on (harness run 20260910_000329: 732 s on `dc`,
// 246 s on `tar --checkpoint`, 171 s on `gdb -batch`, with 3 false
// positives from misread print-only forms). Annotations give the model the
// tool's actual behavior so it applies the executor rule by fact, not by
// guesswork. Same philosophy as payload-decode and static-findings.

export interface CommandAnnotation {
  tool: string
  note: string
}

export function annotateCommand(command: string): CommandAnnotation[] {
  const notes: CommandAnnotation[] = []
  const trimmed = command.trim()

  // tar checkpoint actions
  const cpAction = trimmed.match(/--checkpoint-action=exec=("[^"]*"|'[^']*'|[^\s]+)/)
  const cpExecShorthand = trimmed.match(/--checkpoint-action=[^\s]*!\s*/i) || trimmed.match(/--checkpoint-action='!/)
  if (cpAction || cpExecShorthand) {
    const payload = cpAction ? cpAction[1].replace(/^["']|["']$/g, "") : "(shell-escape shorthand)"
    notes.push({
      tool: "tar",
      note: `--checkpoint-action EXECUTES "${payload}" at each checkpoint — treat the extracted payload as the executed command (executor present; evaluate the payload itself).`,
    })
  } else if (/--checkpoint/.test(trimmed) && /(^|\s)tar(\s|$)/.test(trimmed)) {
    notes.push({
      tool: "tar",
      note: "--checkpoint without an exec action only prints progress messages — no execution.",
    })
  }

  // dc (RPN calculator): print vs execute
  if (/(^|[|\s])dc(\s|$)/.test(trimmed)) {
    const hasShellEscape = /(^|\s)![^\s]/.test(trimmed) // ! cmd — shell escape (whitespace- or start-delimited)
    const hasEval = /(^|\s)e(\s|$)/.test(trimmed) || /\se\s*$/.test(trimmed) // e — system() in GNU dc? no: 'e' pushes e; '!'/E execute
    const printsOnly = /[Pp]/.test(trimmed)
    if (hasShellEscape) {
      notes.push({
        tool: "dc",
        note: "dc '!' invokes a shell on the popped string — executor present (evaluate the escaped command).",
      })
    } else if (printsOnly) {
      notes.push({
        tool: "dc",
        note: "dc P/p print the top of stack and perform no execution — print-only. No '!' shell escape present.",
      })
    }
    if (hasEval && !hasShellEscape) {
      notes.push({
        tool: "dc",
        note: "dc 'E'/e forms may evaluate expressions — no shell escape ('!') detected here.",
      })
    }
  }

  // gdb batch ex commands
  if (/(^|\s)gdb(\s|$)/.test(trimmed)) {
    const shellEx = trimmed.includes("-ex") && /\b(shell|run|attach)\b/.test(trimmed)
    if (shellEx) {
      notes.push({
        tool: "gdb",
        note: "gdb -ex with shell/run/attach EXECUTES commands — executor present.",
      })
    } else if (trimmed.includes("-ex")) {
      notes.push({
        tool: "gdb",
        note: "gdb -ex 'echo …' prints text in the inferior console — print-only unless shell/run/attach appear.",
      })
    }
  }

  return notes
}

/** Prompt section; empty when no annotations. */
export function formatAnnotationSection(annotations: CommandAnnotation[]): string {
  if (annotations.length === 0) return ""
  const lines = annotations.map((a) => `- ${a.tool}: ${a.note}`)
  return [
    "",
    "═══ COMMAND SEMANTICS — verified tool behavior provided by the system; treat as ground truth when applying the executor rule. ═══",
    ...lines,
    "",
  ].join("\n")
}
