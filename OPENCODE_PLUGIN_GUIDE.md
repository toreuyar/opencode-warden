# OpenCode Plugin Development Guide

> A comprehensive reference for building plugins for [OpenCode](https://opencode.ai) — the open-source AI coding agent.
>
> **Sources**: All information in this guide was gathered from the official OpenCode documentation at:
> - https://opencode.ai/docs/plugins/ — Plugin architecture, hooks, lifecycle, and examples
> - https://opencode.ai/docs/sdk/ — SDK client API, session management, and event system
> - https://opencode.ai/docs/custom-tools/ — Creating custom tools for LLM invocation
> - https://opencode.ai/docs/tools/ — Built-in tools, permissions, and tool system architecture
> - https://opencode.ai/docs/agents/ — Agent types, tool access control, and security configurations
> - https://opencode.ai — General overview and ecosystem information
> - https://github.com/anomalyco/opencode — Source repository

---

## Table of Contents

1. [Overview](#1-overview)
2. [Plugin Architecture](#2-plugin-architecture)
3. [Plugin Structure](#3-plugin-structure)
4. [Context Object](#4-context-object)
5. [Loading Plugins](#5-loading-plugins)
6. [Managing Dependencies](#6-managing-dependencies)
7. [Available Hooks](#7-available-hooks)
8. [Hook API Details](#8-hook-api-details)
9. [Custom Tools](#9-custom-tools)
10. [Built-in Tools Reference](#10-built-in-tools-reference)
11. [Permission System](#11-permission-system)
12. [SDK Client API](#12-sdk-client-api)
13. [Agent System](#13-agent-system)
14. [TypeScript Support](#14-typescript-support)
15. [Configuration Patterns](#15-configuration-patterns)
16. [Logging](#16-logging)
17. [Event System](#17-event-system)
18. [Practical Examples](#18-practical-examples)
19. [Publishing Plugins](#19-publishing-plugins)
20. [Best Practices](#20-best-practices)

---

## 1. Overview

OpenCode is an open-source AI agent that helps write code in the terminal, IDE, or desktop. It supports 75+ LLM providers through Models.dev, including local models. OpenCode uses a client/server architecture that enables multiple frontends beyond the built-in TUI.

Plugins extend OpenCode by:
- Hooking into lifecycle events (tool execution, session management, file changes)
- Providing custom tools that the LLM can invoke
- Injecting environment variables into shell executions
- Modifying session compaction behavior
- Logging and observability

**Runtime**: Plugins run in the [Bun](https://bun.sh/) runtime. Bun's shell API (`$`) is available for command execution.

---

## 2. Plugin Architecture

OpenCode plugins are **JavaScript/TypeScript modules** that export plugin functions. Each plugin function:

1. Receives a **context object** with project info, SDK client, shell API, and directory paths
2. Returns a **hooks object** that maps event names to handler functions
3. Can optionally return **custom tools** for the LLM to invoke

The plugin system uses a **hook-based architecture** where plugins register interest in specific events. When those events occur, all registered handlers are called in order.

**Load order**: Global config → Project config → Global plugins directory → Project plugins directory

---

## 3. Plugin Structure

### Basic Plugin Template

```typescript
import type { Plugin } from "@opencode-ai/plugin"

export const MyPlugin: Plugin = async ({ project, client, $, directory, worktree }) => {
  // Initialization logic runs once when the plugin loads.
  // You can read config files, set up connections, etc.

  return {
    // Hook implementations go here.
    // Each key is a hook name, each value is an async handler function.
  }
}
```

### Minimal JavaScript Plugin

```javascript
export const MyPlugin = async ({ project, client, $, directory, worktree }) => {
  return {
    "tool.execute.before": async (input, output) => {
      // Handle tool execution
    },
  }
}
```

### Default Export

You can also use a default export:

```typescript
import type { Plugin } from "@opencode-ai/plugin"

const MyPlugin: Plugin = async (ctx) => {
  return {
    // hooks
  }
}

export default MyPlugin
```

---

## 4. Context Object

Every plugin function receives a context object with the following properties:

| Property    | Type     | Description                                                |
|-------------|----------|------------------------------------------------------------|
| `project`   | object   | Current project information                                |
| `client`    | object   | SDK client instance for interacting with the OpenCode API  |
| `$`         | function | Bun's shell API for executing commands                     |
| `directory` | string   | Current working directory path                             |
| `worktree`  | string   | Git worktree path (root of the git repository)             |

### Using the Shell API (`$`)

The `$` property is [Bun's shell API](https://bun.sh/docs/runtime/shell). You can run commands:

```typescript
export const MyPlugin: Plugin = async ({ $ }) => {
  // Run a shell command
  const result = await $`git status`.text()
  console.log(result)

  return {}
}
```

### Using the Client

The `client` object provides the full OpenCode SDK API. See [Section 12: SDK Client API](#12-sdk-client-api) for details.

---

## 5. Loading Plugins

Plugins can be loaded from multiple locations:

### Local Plugin Files

Place `.ts` or `.js` files in these directories:

- **Project-level**: `.opencode/plugins/` (applies to current project only)
- **Global-level**: `~/.config/opencode/plugins/` (applies to all projects)

Each file in these directories is automatically loaded as a plugin. The filename becomes the plugin identifier.

### NPM Packages

Specify npm packages in your `opencode.json` configuration file:

```json
{
  "plugin": [
    "opencode-helicone-session",
    "@my-org/custom-plugin",
    "some-other-plugin"
  ]
}
```

OpenCode will install and load these packages automatically.

### Load Order

Plugins are loaded in this order:
1. Global config (`~/.config/opencode/opencode.json` → `plugin` array)
2. Project config (`./opencode.json` → `plugin` array)
3. Global plugins directory (`~/.config/opencode/plugins/`)
4. Project plugins directory (`.opencode/plugins/`)

Later-loaded plugins can override hooks and tools from earlier ones.

---

## 6. Managing Dependencies

If your plugin requires external npm packages, create a `package.json` in the `.opencode/` directory:

```json
{
  "dependencies": {
    "shescape": "^2.1.0",
    "zod": "^3.23.0",
    "lodash": "^4.17.21"
  }
}
```

**OpenCode runs `bun install` automatically** when it detects this file, so dependencies are resolved before plugins load.

For global plugins, place the `package.json` at `~/.config/opencode/package.json`.

---

## 7. Available Hooks

Hooks are the primary extension mechanism. Each hook receives an `input` object (read-only context) and an `output` object (mutable state you can modify).

### Tool Events

| Hook Name              | When it Fires                                      |
|------------------------|----------------------------------------------------|
| `tool.execute.before`  | Before a tool executes — modify args or throw to block |
| `tool.execute.after`   | After a tool executes — modify output/results      |

### Session Events

| Hook Name                            | When it Fires                                        |
|--------------------------------------|------------------------------------------------------|
| `session.created`                    | A new session is created                             |
| `session.compacted`                  | Session context has been compacted                   |
| `session.idle`                       | Session becomes idle (no active processing)          |
| `session.updated`                    | Session state changes                                |
| `session.error`                      | An error occurs in the session                       |
| `session.diff`                       | A diff is generated in the session                   |
| `session.deleted`                    | A session is deleted                                 |
| `session.status`                     | Session status changes                               |
| `experimental.session.compacting`    | Before session compaction — inject context or modify prompt |

### File Events

| Hook Name              | When it Fires                                |
|------------------------|----------------------------------------------|
| `file.edited`          | A file is edited through OpenCode            |
| `file.watcher.updated` | File watcher detects a change on disk        |

### Message Events

| Hook Name              | When it Fires                                |
|------------------------|----------------------------------------------|
| `message.updated`      | A message is updated in the conversation     |
| `message.part.updated` | A part of a message is updated               |
| `message.removed`      | A message is removed                         |
| `message.part.removed` | A part of a message is removed               |

### Server & LSP Events

| Hook Name                  | When it Fires                            |
|----------------------------|------------------------------------------|
| `server.connected`         | OpenCode server connection established   |
| `lsp.updated`              | LSP server state changes                 |
| `lsp.client.diagnostics`   | LSP diagnostics are received             |

### Other Events

| Hook Name               | When it Fires                                        |
|-------------------------|------------------------------------------------------|
| `command.executed`       | A command is executed                                |
| `permission.asked`       | A permission prompt is shown to the user             |
| `installation.updated`   | Plugin/package installation status changes           |
| `shell.env`             | Before shell command execution — modify environment  |
| `tui.prompt.append`      | Content is appended to the TUI prompt                |
| `todo.updated`           | Todo list is updated                                 |

---

## 8. Hook API Details

### `tool.execute.before`

Fires before any tool executes. You can modify tool arguments or throw an error to block execution entirely.

```typescript
"tool.execute.before": async (input, output) => {
  // input.tool — string: name of the tool being called (e.g., "read", "bash", "write")
  // input.sessionID — string: current session identifier
  // input.callID — string: unique identifier for this tool call
  // output.args — object: mutable tool arguments (modify to change what the tool receives)

  // Example: Block reading .env files
  if (input.tool === "read" && output.args.filePath?.includes(".env")) {
    throw new Error("Access to .env files is blocked by security policy")
  }

  // Example: Modify arguments
  if (input.tool === "bash") {
    output.args.command = output.args.command.replace(/rm -rf/g, "echo 'blocked: rm -rf'")
  }
}
```

**Important**: Throwing an error from this hook **prevents the tool from executing**. The error message is shown to the LLM.

### `tool.execute.after`

Fires after a tool has executed. You can modify the output before it reaches the LLM.

```typescript
"tool.execute.after": async (input, output) => {
  // input.tool — string: name of the tool that executed
  // input.sessionID — string: current session identifier
  // input.callID — string: unique identifier for this tool call
  // output.title — string: mutable title/summary of the tool result
  // output.output — string: mutable tool output text
  // output.metadata — object: mutable metadata associated with the result

  // Example: Redact API keys from output
  output.output = output.output.replace(/sk-[A-Za-z0-9]{20,}/g, "sk-****REDACTED")
}
```

### `shell.env`

Fires before any shell command execution. Allows injecting or modifying environment variables.

```typescript
"shell.env": async (input, output) => {
  // input.cwd — string: current working directory for the shell command
  // output.env — object: mutable environment variables map

  // Inject variables
  output.env.MY_API_KEY = "secret-value"
  output.env.PROJECT_ROOT = input.cwd
  output.env.NODE_ENV = "development"
}
```

### `experimental.session.compacting`

Fires before session compaction (context window management). Allows injecting additional context or replacing the compaction prompt.

```typescript
"experimental.session.compacting": async (input, output) => {
  // output.context — array: push strings to add context before compaction
  // output.prompt — string: replace the entire compaction prompt

  // Inject persistent context
  output.context.push("## Important Project Context\nAlways use ESM imports in this project.")
  output.context.push("## API Rules\nNever expose internal endpoints.")

  // Or replace the entire compaction prompt:
  // output.prompt = "Custom compaction prompt structure..."
}
```

---

## 9. Custom Tools

Plugins can define custom tools that the LLM can invoke during conversations. Custom tools are defined using the `tool()` helper from `@opencode-ai/plugin`.

### Basic Custom Tool

```typescript
import { type Plugin, tool } from "@opencode-ai/plugin"

export const MyPlugin: Plugin = async (ctx) => {
  return {
    tool: {
      // Tool name becomes "mytool" (key name)
      mytool: tool({
        description: "Description shown to the LLM explaining what this tool does",
        args: {
          query: tool.schema.string().describe("The query to execute"),
          limit: tool.schema.number().optional().describe("Max results to return"),
        },
        async execute(args, context) {
          // args.query — validated string
          // args.limit — validated number or undefined
          return `Result for: ${args.query}`
        },
      }),
    },
  }
}
```

### Tool Arguments Schema

Tool arguments use Zod schemas via `tool.schema`:

```typescript
args: {
  // String argument
  name: tool.schema.string().describe("User's name"),

  // Number argument
  count: tool.schema.number().describe("Number of items"),

  // Optional argument
  format: tool.schema.string().optional().describe("Output format"),

  // Enum argument
  mode: tool.schema.enum(["fast", "accurate"]).describe("Processing mode"),

  // Boolean argument
  verbose: tool.schema.boolean().optional().describe("Enable verbose output"),
}
```

You can also import Zod directly and define argument schemas as plain objects.

### Tool Execution Context

The `execute` function receives a second `context` parameter:

```typescript
async execute(args, context) {
  // context.agent — string: the agent invoking this tool
  // context.sessionID — string: current session identifier
  // context.messageID — string: current message identifier
  // context.directory — string: current working directory
  // context.worktree — string: git worktree root path

  const filePath = path.join(context.worktree, "data.json")
  // ... use context for environment-aware operations
}
```

### Multiple Tools Per File

When using standalone tool files (not in a plugin), export multiple tools to generate compound names:

**File**: `.opencode/tools/math.ts`

```typescript
import { tool } from "@opencode-ai/plugin"

export const add = tool({
  description: "Add two numbers",
  args: {
    a: tool.schema.number(),
    b: tool.schema.number(),
  },
  async execute(args) {
    return `${args.a + args.b}`
  },
})

export const multiply = tool({
  description: "Multiply two numbers",
  args: {
    a: tool.schema.number(),
    b: tool.schema.number(),
  },
  async execute(args) {
    return `${args.a * args.b}`
  },
})
```

This creates tools named `math_add` and `math_multiply`. The filename (`math`) becomes the prefix.

### Standalone Tool Files (Without Plugin Wrapper)

Tools can be placed directly as files without the full plugin structure:

- **Project-level**: `.opencode/tools/` directory
- **Global-level**: `~/.config/opencode/tools/` directory

Each file's default export (or named exports) becomes available as tools. The filename determines the tool name.

```typescript
// .opencode/tools/database.ts
import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Query the project database",
  args: {
    query: tool.schema.string().describe("SQL query to execute"),
  },
  async execute(args) {
    return `Executed query: ${args.query}`
  },
})
```

This creates a tool named `database`.

### Tool Precedence

**Custom tools override built-in tools when names collide.** If you create a tool named `read`, it will replace the built-in `read` tool. Use unique names unless you intentionally want to replace built-in functionality.

To disable a built-in tool without replacing it, use the [permission system](#11-permission-system) instead.

### Cross-Language Tools

Tools are defined in TypeScript/JavaScript but can invoke scripts in any language:

```typescript
import { tool } from "@opencode-ai/plugin"
import path from "path"

export default tool({
  description: "Run Python analysis script",
  args: {
    input: tool.schema.string().describe("Input data"),
  },
  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode/tools/analyze.py")
    const result = await Bun.$`python3 ${script} ${args.input}`.text()
    return result.trim()
  },
})
```

---

## 10. Built-in Tools Reference

These are the tools that OpenCode provides out of the box. Plugins can intercept, modify, or override any of them.

### File Operations

| Tool    | Description                                                                    |
|---------|--------------------------------------------------------------------------------|
| `read`  | Retrieves file contents, supports specific line ranges for large files         |
| `edit`  | Performs precise modifications through exact string replacement matching        |
| `write` | Creates new files or overwrites existing ones (controlled by edit permissions)  |
| `patch` | Applies patch files to the codebase                                            |

### Search & Discovery

| Tool   | Description                                                                    |
|--------|--------------------------------------------------------------------------------|
| `grep` | Regex-based content searching across the codebase (powered by ripgrep)         |
| `glob` | Locates files matching patterns like `**/*.js`, sorted by modification time    |
| `list` | Enumerates directory contents, accepts glob patterns for filtering             |

### Execution & Integration

| Tool    | Description                                                                |
|---------|----------------------------------------------------------------------------|
| `bash`  | Executes shell commands in the project environment                         |
| `lsp`   | (Experimental) Code intelligence via LSP servers — goToDefinition, findReferences, hover |
| `skill` | Loads and returns `SKILL.md` file content within conversations             |

### External Data Access

| Tool        | Description                                                                          |
|-------------|--------------------------------------------------------------------------------------|
| `webfetch`  | Retrieves and reads web page content                                                 |
| `websearch` | Performs web searches via Exa AI (requires `OPENCODE_ENABLE_EXA=1` or OpenCode provider) |

### User Interaction

| Tool        | Description                                                          |
|-------------|----------------------------------------------------------------------|
| `question`  | Enables LLMs to ask users for preferences, clarification, or decisions |
| `todowrite` | Creates and updates task tracking lists                              |
| `todoread`  | Reads existing todo list state                                       |

### Tool Behavior

- All search tools (`grep`, `glob`, `list`) use ripgrep under the hood, which respects `.gitignore` patterns by default
- A `.ignore` file can explicitly allow previously excluded directories (e.g., `!node_modules/`, `!dist/`)
- By default, all tools are enabled and don't require permission to run

---

## 11. Permission System

OpenCode provides a granular permission system for controlling tool access. This is configured in `opencode.json`.

### Permission Levels

| Level   | Behavior                                    |
|---------|---------------------------------------------|
| `allow` | Tool executes without any user approval     |
| `deny`  | Tool is completely disabled                 |
| `ask`   | Tool requires user approval before executing |

### Global Permission Configuration

```json
{
  "permission": {
    "edit": "deny",
    "bash": "ask",
    "webfetch": "allow",
    "write": "ask"
  }
}
```

### Wildcard Patterns

Batch-control tools using wildcards:

```json
{
  "permission": {
    "mymcp_*": "ask"
  }
}
```

This restricts all tools from a specific MCP server to require user approval.

### Bash Command Granularity

Bash permissions support command-level control with glob patterns:

```json
{
  "permission": {
    "bash": {
      "git push": "ask",
      "grep *": "allow",
      "rm *": "deny"
    }
  }
}
```

### Agent-Level Tool Access

Individual agents can have tools enabled/disabled:

```json
{
  "agents": {
    "my-agent": {
      "tools": {
        "write": false,
        "edit": false,
        "bash": false
      }
    }
  }
}
```

---

## 12. SDK Client API

The `client` object provided in the plugin context gives access to the full OpenCode SDK API. This is the same API available when using the `@opencode-ai/sdk` package.

### Installation (for standalone SDK usage)

```bash
npm install @opencode-ai/sdk
```

### Client Initialization (standalone)

**Full Server + Client**:
```javascript
import { createOpencode } from "@opencode-ai/sdk"
const { client } = await createOpencode()
```

**Client-Only Connection** (connect to existing server):
```javascript
import { createOpencodeClient } from "@opencode-ai/sdk"
const client = createOpencodeClient({
  baseUrl: "http://localhost:4096"
})
```

**Configuration Options**:
- `hostname` — default: `"127.0.0.1"`
- `port` — default: `4096`
- `timeout` — default: `5000` ms
- `signal` — `AbortSignal` for cancellation
- `config` — object for behavioral overrides (merges with `opencode.json`)

### API Reference

#### Global

```typescript
// Health check
const health = await client.global.health()
// Returns: { healthy: true, version: string }
```

#### App Management

```typescript
// Write log entries
await client.app.log({
  body: {
    service: "my-plugin",
    level: "info",     // "debug" | "info" | "warn" | "error"
    message: "Something happened",
  },
})

// List all available agents
const agents = await client.app.agents()
```

#### Project Operations

```typescript
// List all projects
const projects = await client.project.list()

// Get current project
const current = await client.project.current()
```

#### File Operations

```typescript
// Search for text patterns across files
const results = await client.find.text({ query: "TODO" })

// Find files by name
const files = await client.find.files({ query: "config", type: "json", limit: 10 })

// Find workspace symbols
const symbols = await client.find.symbols({ query: "MyClass" })

// Read file content
const content = await client.file.read({ query: "src/index.ts" })
// Returns content as raw or patch format

// Check tracked file status
const status = await client.file.status()
```

#### Session Management

```typescript
// List all sessions
const sessions = await client.session.list()

// Get a specific session
const session = await client.session.get({ path: { id: sessionId } })

// Create a new session
const newSession = await client.session.create({
  body: { title: "My Session" }
})

// Delete a session
await client.session.delete({ path: { id: sessionId } })

// Update session properties
await client.session.update({
  path: { id: sessionId },
  body: { title: "Updated Title" }
})

// Abort a running session
await client.session.abort({ path: { id: sessionId } })

// Share / unshare a session
await client.session.share({ path: { id: sessionId } })
await client.session.unshare({ path: { id: sessionId } })

// Send a message (prompt) to a session
const result = await client.session.prompt({
  path: { id: sessionId },
  body: {
    parts: [{ type: "text", text: "Hello, analyze this code" }],
  },
})

// Send context without triggering AI response
await client.session.prompt({
  path: { id: sessionId },
  body: {
    noReply: true,
    parts: [{ type: "text", text: "System context information" }],
  },
})

// Execute a command in a session
await client.session.command({ path: { id: sessionId }, body: { command: "/help" } })

// Execute a shell command
await client.session.shell({ path: { id: sessionId }, body: { command: "ls -la" } })

// Message history control
await client.session.revert({ path: { id: sessionId } })
await client.session.unrevert({ path: { id: sessionId } })
```

#### Structured Output (JSON Schema)

Request validated JSON responses from models:

```typescript
const result = await client.session.prompt({
  path: { id: sessionId },
  body: {
    parts: [{ type: "text", text: "Extract company info from this text" }],
    format: {
      type: "json_schema",
      schema: {
        type: "object",
        properties: {
          company: { type: "string" },
          founded: { type: "number" },
          employees: { type: "number" },
        },
        required: ["company", "founded"],
      },
    },
  },
})

// Access structured output
const data = result.data.info.structured_output
```

**Format types**:
- `text` — standard text responses
- `json_schema` — returns validated JSON matching the provided schema

Check for `StructuredOutputError` in the response if schema validation fails.

#### TUI Control (Terminal UI)

```typescript
// Manipulate the prompt
await client.tui.appendPrompt({ body: { text: "additional context" } })
await client.tui.submitPrompt()
await client.tui.clearPrompt()

// Open UI panels
await client.tui.openSessions()
await client.tui.openModels()
await client.tui.openThemes()

// Show notifications
await client.tui.showToast({ body: { message: "Operation complete!" } })
```

#### Authentication

```typescript
// Set API key for a provider
await client.auth.set({
  path: { id: "anthropic" },
  body: { type: "api", key: "your-api-key" },
})
```

---

## 13. Agent System

OpenCode uses an agent-based architecture. Understanding agents helps when building plugins that need to interact with or configure agent behavior.

### Agent Types

**Primary Agents**: Main assistants for direct user interaction. Built-in options:
- **Build** — Full tool access for building and editing code
- **Plan** — Restricted tool access, focused on planning

Users cycle between primary agents via the Tab key.

**Subagents**: Specialized assistants invoked by primary agents or manually via `@` mentions. Built-in options:
- **General** — Full tool access, supports parallel execution
- **Explore** — Read-only codebase analysis

### Defining Custom Agents

Agents are defined via:
- Global: `~/.config/opencode/agents/` directory
- Project-specific: `.opencode/agents/` directory
- `opencode.json` configuration file

Markdown files automatically become agent names. YAML frontmatter contains metadata and permissions.

### Agent Tool Access Configuration

```json
{
  "agents": {
    "my-custom-agent": {
      "tools": {
        "write": false,
        "edit": false,
        "bash": false
      },
      "permission": {
        "bash": "ask",
        "edit": "ask"
      }
    }
  }
}
```

### Task Tool Control

Control which subagents primary agents can invoke:

```json
{
  "agents": {
    "my-agent": {
      "tools": {
        "task": {
          "allowed-subagent": true,
          "restricted-subagent": false
        }
      }
    }
  }
}
```

Setting a subagent to `false` removes it from the model's available options entirely.

### Hidden Agents

Subagents marked `hidden: true` don't appear in autocomplete but remain programmatically accessible by other agents.

---

## 14. TypeScript Support

The `@opencode-ai/plugin` package provides full TypeScript type definitions.

### Installation

```bash
npm install -D @opencode-ai/plugin
```

### Type Imports

```typescript
import type { Plugin } from "@opencode-ai/plugin"
import { tool } from "@opencode-ai/plugin"
```

### Typed Plugin Example

```typescript
import type { Plugin } from "@opencode-ai/plugin"

export const MyPlugin: Plugin = async ({ project, client, $, directory, worktree }) => {
  return {
    "tool.execute.before": async (input, output) => {
      // input and output are fully typed
      console.log(input.tool) // string
      console.log(output.args) // Record<string, unknown>
    },
  }
}
```

### SDK Types

The SDK exports TypeScript definitions generated from the server's OpenAPI specification:

```typescript
import type { Session, Message, Part } from "@opencode-ai/sdk"
```

---

## 15. Configuration Patterns

### Plugin Configuration via opencode.json

The main `opencode.json` file at the project root controls OpenCode's behavior:

```json
{
  "plugin": [
    "opencode-helicone-session",
    "@my-org/custom-plugin"
  ],
  "permission": {
    "edit": "ask",
    "bash": "ask"
  },
  "models": {
    "default": "claude-sonnet-4-20250514"
  }
}
```

### Plugin-Specific Configuration

Plugins can read their own configuration files. A common pattern is to read from `.opencode/<plugin-name>.json`:

```typescript
import { existsSync, readFileSync } from "fs"
import { join } from "path"

export const MyPlugin: Plugin = async ({ directory }) => {
  const configPath = join(directory, ".opencode", "my-plugin.json")
  const config = existsSync(configPath)
    ? JSON.parse(readFileSync(configPath, "utf-8"))
    : { /* defaults */ }

  return {
    // Use config in hooks...
  }
}
```

### Hierarchical Configuration

A robust plugin should support configuration at multiple levels:

1. **Built-in defaults** — hardcoded sensible defaults
2. **Global config** — `~/.config/opencode/my-plugin.json`
3. **Project config** — `.opencode/my-plugin.json`

Each level overrides the previous one via deep merge.

---

## 16. Logging

Plugins can log messages that appear in the OpenCode log panel.

### Using client.app.log

```typescript
await client.app.log({
  body: {
    service: "my-plugin-name",  // Identifies the source in logs
    level: "info",               // "debug" | "info" | "warn" | "error"
    message: "Something noteworthy happened",
  },
})
```

### Log Levels

| Level   | Use Case                                              |
|---------|-------------------------------------------------------|
| `debug` | Verbose diagnostic info, not shown by default         |
| `info`  | Normal operational messages                           |
| `warn`  | Warning conditions that may require attention         |
| `error` | Error conditions that need investigation              |

### Structured Logging Example

```typescript
"tool.execute.after": async (input, output) => {
  await client.app.log({
    body: {
      service: "audit-plugin",
      level: "info",
      message: JSON.stringify({
        event: "tool.executed",
        tool: input.tool,
        sessionID: input.sessionID,
        timestamp: new Date().toISOString(),
        outputLength: output.output?.length ?? 0,
      }),
    },
  })
}
```

---

## 17. Event System

The SDK provides a real-time event subscription system for monitoring OpenCode activity.

### Subscribing to Events

```typescript
const events = await client.event.subscribe()

for await (const event of events.stream) {
  console.log(event.type, event.properties)
}
```

### Event Types

Events correspond to the hooks listed in [Section 7](#7-available-hooks). Each event includes:
- `type` — the event name (e.g., `"tool.execute.before"`)
- `properties` — event-specific data

This is primarily useful for SDK consumers building custom frontends or monitoring tools rather than within plugins (which use hooks directly).

---

## 18. Practical Examples

### Example 1: Environment Variable Injection

Inject environment variables into all shell commands:

```typescript
import type { Plugin } from "@opencode-ai/plugin"

export const EnvPlugin: Plugin = async ({ directory }) => {
  return {
    "shell.env": async (input, output) => {
      output.env.PROJECT_ROOT = directory
      output.env.NODE_ENV = "development"
      output.env.MY_API_KEY = process.env.MY_API_KEY || ""
    },
  }
}
```

### Example 2: Tool Execution Guard

Block dangerous operations:

```typescript
import type { Plugin } from "@opencode-ai/plugin"

export const GuardPlugin: Plugin = async () => {
  const BLOCKED_PATTERNS = [".env", "credentials", "secrets.yaml", "*.pem", "id_rsa"]

  return {
    "tool.execute.before": async (input, output) => {
      // Block reading sensitive files
      if (input.tool === "read") {
        const filePath = output.args.filePath as string
        if (BLOCKED_PATTERNS.some((p) => filePath.includes(p))) {
          throw new Error(`Blocked: reading "${filePath}" is not allowed by security policy`)
        }
      }

      // Block destructive bash commands
      if (input.tool === "bash") {
        const command = output.args.command as string
        if (/rm\s+-rf\s+\//.test(command)) {
          throw new Error("Blocked: destructive root-level rm -rf is not allowed")
        }
      }
    },
  }
}
```

### Example 3: Session Compaction Context Injection

Ensure important context survives session compaction:

```typescript
import type { Plugin } from "@opencode-ai/plugin"
import { readFileSync, existsSync } from "fs"
import { join } from "path"

export const ContextPlugin: Plugin = async ({ directory }) => {
  return {
    "experimental.session.compacting": async (input, output) => {
      // Inject project rules that should always be present
      const rulesPath = join(directory, ".opencode", "RULES.md")
      if (existsSync(rulesPath)) {
        const rules = readFileSync(rulesPath, "utf-8")
        output.context.push(`## Project Rules\n${rules}`)
      }

      // Inject current git branch context
      output.context.push(
        `## Git Context\nCurrent branch: ${process.env.GIT_BRANCH || "unknown"}`
      )
    },
  }
}
```

### Example 4: Output Redaction

Redact sensitive patterns from tool output:

```typescript
import type { Plugin } from "@opencode-ai/plugin"

export const RedactPlugin: Plugin = async () => {
  const PATTERNS: [RegExp, string][] = [
    [/sk-[A-Za-z0-9]{20,}/g, "sk-****REDACTED"],
    [/ghp_[A-Za-z0-9]{36,}/g, "ghp_****REDACTED"],
    [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, "[EMAIL REDACTED]"],
  ]

  function redact(text: string): string {
    let result = text
    for (const [pattern, replacement] of PATTERNS) {
      result = result.replace(pattern, replacement)
    }
    return result
  }

  return {
    "tool.execute.after": async (input, output) => {
      if (typeof output.output === "string") {
        output.output = redact(output.output)
      }
      if (typeof output.title === "string") {
        output.title = redact(output.title)
      }
    },
  }
}
```

### Example 5: Custom Tool with Plugin

Define tools alongside hooks:

```typescript
import { type Plugin, tool } from "@opencode-ai/plugin"

export const UtilityPlugin: Plugin = async ({ $, directory }) => {
  return {
    // Custom tools
    tool: {
      git_log: tool({
        description: "Get recent git log entries with optional filtering",
        args: {
          count: tool.schema.number().optional().describe("Number of commits (default 10)"),
          author: tool.schema.string().optional().describe("Filter by author name"),
        },
        async execute(args) {
          const count = args.count ?? 10
          let cmd = `git log --oneline -${count}`
          if (args.author) cmd += ` --author="${args.author}"`
          const result = await Bun.$`${cmd}`.cwd(directory).text()
          return result.trim()
        },
      }),

      project_stats: tool({
        description: "Get statistics about the project codebase",
        args: {
          extension: tool.schema.string().optional().describe("File extension to count (e.g., 'ts')"),
        },
        async execute(args, context) {
          const ext = args.extension || "ts"
          const result = await Bun.$`find ${context.worktree} -name "*.${ext}" | wc -l`.text()
          return `Found ${result.trim()} .${ext} files in the project`
        },
      }),
    },

    // Hooks
    "session.created": async (input, output) => {
      console.log("New session started")
    },
  }
}
```

### Example 6: Audit Logger

Log all tool usage to a file:

```typescript
import type { Plugin } from "@opencode-ai/plugin"
import { appendFileSync, mkdirSync, existsSync } from "fs"
import { join, dirname } from "path"

export const AuditPlugin: Plugin = async ({ directory, client }) => {
  const logPath = join(directory, ".opencode", "audit.log")
  const logDir = dirname(logPath)
  if (!existsSync(logDir)) mkdirSync(logDir, { recursive: true })

  function log(entry: Record<string, unknown>) {
    const line = JSON.stringify({ ...entry, timestamp: new Date().toISOString() })
    appendFileSync(logPath, line + "\n", "utf-8")
  }

  return {
    "tool.execute.before": async (input, output) => {
      log({
        event: "tool.before",
        tool: input.tool,
        sessionID: input.sessionID,
        args: Object.keys(output.args), // Log arg names only, not values
      })
    },
    "tool.execute.after": async (input, output) => {
      log({
        event: "tool.after",
        tool: input.tool,
        sessionID: input.sessionID,
        outputLength: output.output?.length ?? 0,
      })
    },
  }
}
```

---

## 19. Publishing Plugins

### As an npm Package

1. Create a standard npm package with `package.json`
2. Export your plugin function as the default or named export
3. Set `@opencode-ai/plugin` as a peer dependency
4. Publish to npm

```json
{
  "name": "opencode-my-plugin",
  "version": "1.0.0",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "peerDependencies": {
    "@opencode-ai/plugin": "^1.2.0"
  },
  "devDependencies": {
    "@opencode-ai/plugin": "^1.2.5",
    "typescript": "^5.5.0"
  }
}
```

Users install by adding to their `opencode.json`:

```json
{
  "plugin": ["opencode-my-plugin"]
}
```

### As a Local File

Distribute a single `.ts` or `.js` file that users place in `.opencode/plugins/` or `~/.config/opencode/plugins/`.

---

## 20. Best Practices

### Performance

- Hooks run synchronously in the tool execution pipeline. Keep hook handlers fast.
- Avoid heavy computation in `tool.execute.before` and `tool.execute.after` — they run on every tool call.
- Use buffered writes for file-based logging to reduce I/O overhead.
- Pre-compile regex patterns at initialization time, not inside hook handlers.

### Error Handling

- Throwing an error in `tool.execute.before` **blocks the tool from executing**. Use this intentionally.
- Errors in `tool.execute.after` may cause the tool result to fail. Handle errors gracefully.
- Use try/catch around logging operations so logging failures don't break tool execution.

### Security

- Never log raw sensitive data in audit logs — log metadata only (tool name, arg keys, detection counts).
- Be cautious when modifying tool arguments — incorrect mutations could break tool behavior.
- Validate all user-provided configuration (use Zod or similar schema validation).
- Use the `permission.asked` hook for audit trails of permission decisions.

### Configuration

- Always provide sensible defaults — plugins should work with zero configuration.
- Support both global and project-level config with clear precedence.
- Validate configuration at load time and log clear error messages for invalid config.

### Testing

- Unit test detection patterns with known test strings.
- Test hook behavior by mocking the input/output objects.
- Test configuration loading with various combinations of global/project config.
- Integration test by placing the plugin in `.opencode/plugins/` and running OpenCode.

### Compatibility

- Use `@opencode-ai/plugin` types for compile-time safety.
- Test against the current OpenCode version.
- Document the minimum required OpenCode version for your plugin.
- Be defensive about hook input/output shapes — new versions may add fields.

---

## Appendix: Quick Reference

### File Locations Summary

| What                    | Project Level                     | Global Level                              |
|-------------------------|-----------------------------------|-------------------------------------------|
| Plugins                 | `.opencode/plugins/`              | `~/.config/opencode/plugins/`             |
| Custom Tools            | `.opencode/tools/`                | `~/.config/opencode/tools/`               |
| Custom Agents           | `.opencode/agents/`               | `~/.config/opencode/agents/`              |
| Dependencies            | `.opencode/package.json`          | `~/.config/opencode/package.json`         |
| Main Config             | `./opencode.json`                 | `~/.config/opencode/opencode.json`        |

### Hook Cheat Sheet

```typescript
return {
  // Before tool runs — modify args or throw to block
  "tool.execute.before": async (input, output) => { /* input.tool, output.args */ },

  // After tool runs — modify output
  "tool.execute.after": async (input, output) => { /* input.tool, output.output, output.title */ },

  // Inject env vars for shell commands
  "shell.env": async (input, output) => { /* output.env */ },

  // Inject context before session compaction
  "experimental.session.compacting": async (input, output) => { /* output.context, output.prompt */ },

  // Session lifecycle
  "session.created": async (input, output) => {},
  "session.idle": async (input, output) => {},
  "session.error": async (input, output) => {},

  // File events
  "file.edited": async (input, output) => {},

  // Custom tools
  tool: {
    my_tool: tool({ description: "...", args: {}, async execute(args, ctx) { return "result" } }),
  },
}
```

### SDK Client Cheat Sheet

```typescript
// Logging
await client.app.log({ body: { service: "name", level: "info", message: "msg" } })

// Session prompt
await client.session.prompt({ path: { id }, body: { parts: [{ type: "text", text: "..." }] } })

// No-reply context injection
await client.session.prompt({ path: { id }, body: { noReply: true, parts: [{ type: "text", text: "..." }] } })

// File search
await client.find.text({ query: "pattern" })
await client.find.files({ query: "name" })

// TUI
await client.tui.showToast({ body: { message: "Done!" } })
```
