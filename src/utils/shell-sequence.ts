import { LangBash, parseSync, Pipe, PipeAll } from "sh-ast"
import type { Stmt } from "sh-ast"
import { canonicalToolName } from "./tool-compat.js"

export const SHELL_SEQUENCE_BLOCK_REASON = "Multiple sequential shell operations in one call"
export const SHELL_SEQUENCE_RETRY = "Submit separate shell calls, specifying the working directory or environment where needed."
export const SHELL_SEQUENCE_BLOCK_MESSAGE = `Warden: ${SHELL_SEQUENCE_BLOCK_REASON}. ${SHELL_SEQUENCE_RETRY}`

function isSimpleCommandOrPipeline(statement: Stmt): boolean {
  const command = statement.Cmd
  return (command?.Type === "CallExpr" && (command.Args?.length ?? 0) > 0) ||
    (command?.Type === "BinaryCmd" && (command.Op === Pipe || command.Op === PipeAll))
}

export function hasSequentialShellBatch(tool: string, command: unknown): boolean {
  if (canonicalToolName(tool) !== "shell" || typeof command !== "string") return false
  if (!command.includes(";") && !command.includes("\n")) return false

  try {
    const statements = parseSync(command, { Variant: LangBash }).Stmts ?? []
    return statements.some((statement, index) => {
      const previous = statements[index - 1]
      // Adjacent root statements are separated by `;`, a command-ending
      // newline, or a background terminator. Pipes and &&/|| are AST nodes,
      // not statement separators; nested statements are never traversed.
      return previous != null && statement != null && !previous.Background && !previous.Coprocess &&
        !statement.Background && !statement.Coprocess &&
        isSimpleCommandOrPipeline(previous) && isSimpleCommandOrPipeline(statement)
    })
  } catch {
    // No finding for syntax this Bash parser cannot classify. The existing
    // enforcement and evaluator still run; this is not an allow verdict.
    return false
  }
}
