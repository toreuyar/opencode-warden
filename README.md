<p align="center">
  <img src="warden-icon.svg" alt="OpenCode Warden" width="200">
</p>

<h1 align="center">OpenCode Warden</h1>

<p align="center">
  <a href="https://github.com/toreuyar/opencode-warden/actions/workflows/test.yml"><img src="https://github.com/toreuyar/opencode-warden/actions/workflows/test.yml/badge.svg" alt="Tests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://opencode.ai"><img src="https://img.shields.io/badge/OpenCode-Plugin-8B5CF6" alt="OpenCode Plugin"></a>
  <a href="https://bun.sh"><img src="https://img.shields.io/badge/Runtime-Bun-f9f1e1" alt="Bun"></a>
</p>

<p align="center">
  A comprehensive security plugin for <a href="https://opencode.ai">OpenCode</a> that intercepts tool calls to detect secrets, redact sensitive data, evaluate safety risks, block access to sensitive files, and maintain a complete audit trail.
</p>

## Compatibility

Warden's version is independent of the OpenCode **host** version. Choose the
Warden line that matches your host's plugin API:

| OpenCode host | Warden plugin | Status |
|---|---|---|
| **OpenCode 1.x** (V1 plugin API) | **1.3.0**, pinned exactly | Last Warden release for OpenCode 1.x. Published with `@opencode-ai/plugin` `^1.2.0`. **Do not install Warden 2.0.0 on OpenCode 1.x.** |
| **OpenCode 2.0.0–2.0.17** | **2.0.0** | **Below the declared supported floor (2.0.18); not verified.** Warden loads with a warning and keeps protections installed, but host compatibility is not guaranteed. |
| **OpenCode 2.0.18–2.0.28** | **2.0.0** | **Supported floor.** Bounded runtime validation of the built plugin with local mocks passed on 2.0.18, including the untyped per-call block path. Clean typed `Tool.Error` vetoes require 2.0.29+. |
| **OpenCode 2.0.29+** | **2.0.0** | Supported. The typed per-call veto mapping introduced in 2.0.29 is source/package-verified; **not runtime-probed on a 2.0.29 or 2.1.4 binary**. See [Verification status](#runtime-boundaries). |

OpenCode 2.x is the target line for Warden 2.0.0, but **not every 2.x host is
verified**. The minimum declared floor is 2.0.18. Warden does not claim that all
OpenCode 2.x versions are certified.

**Bounded runtime results on 2.0.18** (isolated run of the built 2.0.0 with local
mocks): config
precedence and inline fallback, invalid-config lockdown, V2 `path`/`shell`/
`subagent` blocking, write/read/error redaction, outbound tool-result redaction
and policy injection, global shell backstop, evaluator and output-sanitizer
outage blocking in `warn` mode, explicit `llm.enabled: false` deterministic
mode, `session.update({ permissions })` preservation and application, server
RPC/SSE notification delivery, and compaction policy injection plus redaction
with a valid summary. These results do **not** certify every host behavior and
were not run on 2.1.4. A bounded 2.0.18 secret-write replay passed with the structural
tool-call-input projection: exit 0 / `PROBE_DONE`, the file contained
`[REDACTED]`, and the next request had `rawHasDKey:false`,
`historyHasDKey:false`, and the policy present. A bounded 2.0.18 title/generate
replay also passed: the tool-less title request had no policy, sent
`[REDACTED]` instead of the raw key, and persisted `Replay Title` with exit 0;
the public generate request had the policy and normal tools, sent redacted text,
and returned `PROBE_DONE`. These replays are bounded validation, not
certification of every behavior, and do not scrub at-rest input. Live rendered
TUI toasts and the 2.0.29+/2.1.4 binaries remain untested; the
structured-output content path passed at runtime, while the content-less
fallback branch is unit-test only.

## Features

- **65 active built-in detection patterns** across 11 categories — API keys, credentials, private keys, PII, cloud provider secrets, Docker, Kubernetes, and more (66 defined; `pii-ip-address` is off by default)
- **V2-native tool vocabulary** — policies use `shell`, `subagent`, and `path`; legacy `bash`, `task`, and `filePath` configs and callers remain accepted as aliases. `patch` inputs are inspected through every `patchText` add/update/delete/move target
- **Optional user prompt scanning** — opt-in via `scanUserPrompts: true`. When enabled, incoming prompt text plus attachment metadata (file URI/name/description, agent/skill names, mentions) is scanned before it reaches the LLM; prompts containing detected secrets are blocked and never persisted. File contents are deliberately not read. Disabled by default due to upstream TUI limitations on how blocked prompts are surfaced.
- **LLM-powered safety evaluation** across 10 risk dimensions (exfiltration, destruction, privilege escalation, and more)
- **LLM-enhanced output sanitization** — catches context-dependent secrets that regex alone misses
- **Outbound request scanning** — before provider dispatch, `session.context` redacts supported system/message/tool-result text and compaction requests, and injects the security policy as a per-request system part. `session.generate` reuses the same policy, blocked-tool restrictions, and scanning as a primary request; the tool-less `session.title` request gets deterministic redaction without policy injection so title output is preserved. Tool-call ids/names and provider metadata are preserved; historical tool-call input strings are structurally redacted in the request projection, while file/media identifiers are scanned read-only and a detection withholds the request
- **File path blocking** with glob patterns — prevents access to `.env`, `*.pem`, `*.key`, kubeconfig, tfstate, and other sensitive files
- **Global shell backstop** — every shell creation, including the user's own terminals/background shells, is checked against the file blocklist and write-protection lists. This is broader than agent-only enforcement and is intentional
- **Write-protection** for read-only-but-never-modified files (logs, state) — read allowed, writes blocked deterministically including via shell redirections (`>`, `>>`, `tee`, `truncate`)
- **Per-path redaction exemptions** — keep legitimate API keys in source code (client libraries, config templates) without Warden rewriting them to `[REDACTED]`. Covers `write`/`edit`/`patch`, `read`, shell redirections/reads, outbound context results, and SSH/SCP/rsync/rclone operations. Supports host-scoped entries (e.g. `host:web-*:/etc/myapp/**`) for remote-only exemptions
- **Configurable redaction scope** — disable write-time redaction (`redactOnWrite`), or kill all redaction globally (`redactionEnabled`), without losing file blocking or safety evaluation
- **Environment variable sanitization** — strips secrets from the shell environment before they reach tool calls
- **Session deny rules (defense in depth)** — literal blocked tools and literal absolute blocklist/write-protected paths are also translated into session-scoped deny rules where OpenCode can express them exactly. Warden's primary hooks remain authoritative; configured glob/relative paths and shell path policy are intentionally not translated
- **SSH-only mode** — monitor only remote commands (ssh, scp, sftp, rsync, rclone) while bypassing all local operations
- **7 built-in tools** — dashboard, reports, audit queries, dry-run evaluation, config view, and rule management. Plugin tools use OpenCode's Code Mode by default, so the agent invokes them through `execute` (for example `tools.security_help`), not the native provider tool list
- **Three-layer rule architecture** — builtin, user-managed, and AI-managed detection rules
- **Customizable prompts** — replace any LLM prompt via config using `{{variableName}}` templates
- **Zero-config operation** — works out of the box with sensible defaults, no LLM required
- **Comprehensive audit logging** — JSON-line log files with rotation, verbosity levels, and session statistics
- **Configurable action modes** — auto-block, user-prompted permission, or warn-only for both input safety and output sanitization. When the LLM is enabled, an outage still blocks input safety and non-`pass` output paths regardless of the configured mode

## Installation

### Prerequisites

- **OpenCode 2.x** for Warden **2.0.0**. The declared supported floor is
  **OpenCode 2.0.18** (`@opencode/plugin` `^2.0.18`). Development and
  type-checking use the 2.1.4 SDK; the peer range expresses the 2.0.18 API floor
  that Warden's used surface is verified against. Hosts on 2.0.0–2.0.17 are
  below the floor and load with a warning while keeping protections installed.
  On 2.0.18–2.0.28, Warden blocks per call through the older untyped rejection
  path exercised on 2.0.18; clean typed `Tool.Error` vetoes require 2.0.29+.
  Neither the 2.0.29 nor the 2.1.4 binary has been runtime-probed.
- **OpenCode 1.x** requires Warden **1.3.0** (pinned). Warden 2.0.0 uses the V2
  plugin API and is not a drop-in replacement on a V1 host.
- [Bun](https://bun.sh) runtime (OpenCode uses Bun for plugins)

### Install Warden 2.0.0 on OpenCode 2.x

Add the pinned package to the `plugin` array in your OpenCode configuration.
Installing by **package name** is the supported form; OpenCode resolves the
published `exports` correctly:

**Global** (`~/.config/opencode/opencode.json`) — applies to all projects:

```json
{
  "plugin": ["opencode-warden@2.0.0"]
}
```

**Project-level** (`./opencode.json`) — applies to a single project:

```json
{
  "plugin": ["opencode-warden@2.0.0"]
}
```

You may omit `@2.0.0` to track the newest release, but pinning avoids surprise
upgrades. OpenCode installs npm plugins automatically with Bun at startup.

### Install Warden 1.3.0 on OpenCode 1.x

OpenCode 1.x uses the V1 plugin API. Pin the last Warden release for that line:

```json
{
  "plugin": ["opencode-warden@1.3.0"]
}
```

Use the same `plugin` array in either the global or project `opencode.json`.
Warden 1.3.0 is published on npm with peer dependency
`@opencode-ai/plugin` `^1.2.0`. **Do not install `opencode-warden@2.0.0` on
OpenCode 1.x.** An unpinned install can resolve differently after a new release
is tagged `latest`, so pin `1.3.0` explicitly. For the 1.3.0 configuration
reference, use the [v1.3.0 README](https://github.com/toreuyar/opencode-warden/blob/v1.3.0/README.md)
and [v1.3.0 example config](https://github.com/toreuyar/opencode-warden/blob/v1.3.0/opencode-warden.example.json)
rather than this 2.0.0 documentation.

### Install from Source

If you prefer to run from source (for development or customization):

```bash
# Warden 2.0.0 for OpenCode 2.x
git clone https://github.com/toreuyar/opencode-warden.git
cd opencode-warden
bun install
bun run build

# Warden 1.3.0 for OpenCode 1.x
git clone --branch v1.3.0 https://github.com/toreuyar/opencode-warden.git
cd opencode-warden
bun install
```

> **Local-directory entrypoint:** on OpenCode 2.x, when a 2.0.0 `plugin` entry
> points at a local **directory**, OpenCode probes `<directory>/server` and
> `<directory>/index`. It does not read the package's `package.json` `main`/`exports`, so a checkout that only has
> `dist/index.js` loads Warden silently as a no-op. This was reproduced on
> 2.0.18 (the supported floor); the same resolver source is present in 2.1.4.
> Use the package name after a normal npm install, or create root entry files
> from the build:

```bash
cp dist/index.js index.js          # required — server/plugin entrypoint
cp dist/rpc.js rpc.js              # only for the RPC notification surface
cp dist/tui.js tui.js              # only for the TUI companion
```

Then register the plugin by adding its **absolute path** to `opencode.json`:

```json
{
  "plugin": [
    "/absolute/path/to/opencode-warden"
  ]
}
```

Re-run `bun run build` and re-copy the files after source changes. The root
`index.js` is what the local-directory resolver loads; `dist/index.js` alone is
not enough.

> **Note**: The path must be absolute (e.g., `/home/user/opencode-warden` on Linux, `/Users/user/opencode-warden` on macOS). A wrong or non-existent path will cause OpenCode to hang on startup.

### Alternative: Plugin Directory

You can also copy the built plugin **files** into OpenCode's plugin directories:

- **Global**: `~/.config/opencode/plugins/`
- **Project-level**: `.opencode/plugins/`

Place the built entrypoint as a file (for example `index.js`, plus `rpc.js` and
`tui.js` when those surfaces are needed) rather than a package subdirectory.
Files placed in these directories are loaded automatically.

## Quick Start

Warden works with **zero configuration**. Once installed, it immediately:

1. Blocks access to sensitive files (`.env`, `*.pem`, `*.key`, etc.)
2. Scans and redacts secrets in tool inputs and outputs using 65 active regex patterns
3. Sanitizes environment variables before they reach shell commands
4. Scans outbound model requests and compaction requests, and injects the security policy per request
5. Applies a global shell backstop to agent and user shells
6. Logs all security events to `.opencode/warden/audit.log`
7. Provides 7 built-in tools for real-time visibility and rule management through OpenCode Code Mode (`execute` → `tools.security_*`)
8. Sends sanitized alerts through the TUI/RPC companion when `notifications` is enabled (fixed event kinds + bounded tool/count only; no paths, arguments, explanations, or output). Notifications are UX-only and never affect enforcement

To enable LLM-powered safety evaluation (recommended for production use), create a config file:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "your-model-name"
  }
}
```

Place this file at `.opencode/opencode-warden.json` in your project root or `~/.config/opencode/opencode-warden.json` for global settings.

### Configuration precedence and failure behavior

- Configuration is merged as defaults → global file → project file. Arrays are replaced, not appended.
- Inline `ctx.options` are a fallback only when **neither** the global nor project config file exists. If either file exists, inline options are ignored entirely, even when that file is invalid or unreadable — the file always wins.
- Invalid or unreadable configuration does **not** unload Warden. Warden installs a fail-closed lockdown that denies permissions, vetoes tool execution, withholds tool output, and blocks prompts, model requests, compaction, and shell creation until the configuration is fixed and OpenCode is restarted.
- With the LLM enabled, an unreachable/misconfigured evaluator or sanitizer blocks the operation regardless of `actionMode` (`warn` and `permission` do not allow an outage through). The explicit `llm.enabled: false` mode is deterministic-only and does not block because of LLM absence.
- A 2.x runtime below 2.0.18 produces a warning but keeps all protections installed. On 2.0.18–2.0.28, Warden also warns that typed per-call vetoes require 2.0.29+; blocking uses the older untyped path. Warden never refuses setup for a version mismatch, because a failed plugin setup would leave the host entirely unprotected. This does not extend V1 compatibility to OpenCode 1.x.

### Runtime boundaries

- **Hook ordering:** OpenCode runs hooks in registration order with no priority API. Later plugins observe earlier mutations, so Warden cannot guarantee its mutations are final. Treat the host and all loaded plugins as trusted, and load Warden last where possible; registration order alone is not a security boundary.
- **Ephemeral context redaction:** outbound redaction on `session.context`, `session.generate`, `session.title`, and `session.compaction` mutates per-request projections, not stored history. History remains unchanged. Tool-call ids/names, message metadata, and `providerMetadata` are preserved. Historical tool-call input strings are structurally redacted in the projection with ids/names/keys/shape preserved; file/media identifiers and provider-signed/encrypted text are never rewritten, and a required change there aborts the request (fail-closed) instead of corrupting the provider payload. Signature-bearing text can therefore cause a rejected request rather than a silently altered one.
- **Secret-bearing writes and at-rest input:** `write`/`edit`/`patch` input redaction protects the file that is written, but the host persists the model's original tool-call input before `tool.execute.before` runs. The next dispatch structurally redacts detected strings in that historical input for the provider request, so the secret is not forwarded; Warden does **not** rewrite the persisted session store, so the raw input remains at rest. Provider-signed/encrypted or unsupported input shapes abort instead of being rewritten. `redactOnWrite: false` and `redactionExemptPaths` exempt those historical inputs and allow the secret through, so they are not a secure remedy. Prefer not to route real secrets through model-authored writes. A bounded 2.0.18 replay passed with this structural projection (exit 0, next request redacted, policy present); raw pre-hook input remains at rest, and this is not a 2.0.18 or 2.1.4 certification.
- **Auxiliary request coverage:** `session.generate` is scanned with the same policy append, blocked-tool removal, and outbound redaction as a primary request. `session.title` is tool-less and deliberately receives no policy injection; it is scanned and redacted deterministically, and the title result is preserved. A bounded 2.0.18 replay passed both surfaces (title sent `[REDACTED]` and persisted `Replay Title`; generate sent redacted text and returned `PROBE_DONE`). No actual external provider, 2.1.4 binary, or live rendered TUI was used.
- **Verification status:** bounded runtime validation was performed on **OpenCode 2.0.18** (the declared floor) with the built Warden 2.0.0, loaded through a root `index.js` entrypoint and using local mocks rather than an external provider. It passed config precedence and inline fallback, invalid-config lockdown, V2 path/shell/subagent blocking, write/read/error redaction, bounded secret-write replay with structural tool-call-input projection redaction (exit 0, next request redacted, policy present), outbound tool-result redaction and policy injection, title and generate replay (title redacted with no policy and preserved `Replay Title`; generate redacted with policy/tools and returned `PROBE_DONE`), shell backstop, evaluator/sanitizer outage blocking in `warn`, explicit `llm.enabled: false` deterministic mode, `session.update({ permissions })` preservation and application, server RPC/SSE notification delivery, and compaction policy injection plus redaction with a valid summary. These are bounded results, not a certification of every host behavior. They were not run on 2.1.4. The **typed per-call veto mapping** (`Tool.Error`) was introduced in `@opencode/plugin` 2.0.29 and is source/package-verified there and in 2.1.4; on 2.0.18–2.0.28 the host uses the older untyped per-call rejection path, which the 2.0.18 validation exercised. **Live rendered TUI toasts remain untested** (server RPC/SSE delivery passed on 2.0.18). Structured output passed at runtime through the host-normalized content path; the content-less structured fallback branch is unreachable on 2.0.18 and remains unit-test only.
- **Notifications:** UI alerts are UX-only. Enforcement decisions, blocks, and audit records do not depend on a toast or TUI connection succeeding.

## Versioning and upgrading to 2.0.0

**Warden 2.0.0 is the plugin version.** It is separate from the OpenCode host
version. Warden 2.0.0 targets the OpenCode V2 plugin API with a supported host
floor of **OpenCode 2.0.18** (`@opencode/plugin` peer `^2.0.18`, developed and
type-checked against 2.1.4). References to OpenCode 2.0.18 elsewhere describe the
declared floor and the bounded-validation host, not the Warden version.
Typed per-call `Tool.Error` vetoes are available from host 2.0.29; earlier
supported hosts (2.0.18–2.0.28) still block per call through the untyped path.

### Upgrade checklist

1. **Check the host line first.** On **OpenCode 1.x**, do **not** upgrade to
   Warden 2.0.0. Pin `opencode-warden@1.3.0` (see
   [Compatibility](#compatibility)).
2. **Upgrade OpenCode first** on the 2.x line. Use at least a 2.0.18 host. For
   clean typed per-call tool vetoes, use 2.0.29+. Hosts on 2.0.0–2.0.17 are
   below the floor and load with a warning; 2.0.18–2.0.28 load with a
   typed-veto advisory and block through the older untyped path exercised on
   2.0.18.
3. **Upgrade the plugin** to `opencode-warden@2.0.0` and restart OpenCode.
4. **Remove obsolete tool entries.** V2 has no `list` tool, so `excludedTools`
   now defaults to `[]`; delete any `"list"` entry.
5. **Keep legacy config names if you prefer.** `bash`, `task`, and `filePath`
   remain accepted aliases for `shell`, `subagent`, and `path`. New configs
   should use the V2 names.
6. **Review LLM settings.** The default request timeout is `0` (no timeout). Set
   an explicit positive `llm.timeout` when enabling the LLM, and remember that
   an enabled-but-unreachable evaluator now blocks even in `warn`/`permission`.
7. **Check notification delivery.** Alerts use the event-only TUI/RPC contract.
   If you run without the TUI companion, enforcement and audit logging continue
   but UI alerts may be absent.

### Breaking changes and behavior changes

- **OpenCode 1.x is not supported by Warden 2.0.0.** The legacy plugin API and
  `chat.message`/`shell.env`/`permission.ask` integration points are replaced by
  the V2 hook families. OpenCode 1.x users should stay on the pinned 1.3.0
  release.
- Invalid or unreadable configuration installs an active lockdown instead of
  unloading Warden. Inline `ctx.options` are used only when neither config file
  exists.
- An LLM outage is fail-closed for input safety and non-`pass` output paths
  regardless of `actionMode`. Explicit `llm.enabled: false` remains
  deterministic-only.
- Outbound redaction on `session.context`, `session.generate`, `session.title`,
  and `session.compaction` is ephemeral: it protects the request projection, not
  stored conversation history. The raw pre-hook tool-call input for a
  secret-bearing write remains in the session store; redaction of the outbound
  projection is not at-rest scrubbing.
- Outbound scanning now covers `session.generate` with the same policy and
  tool restrictions as a primary request. The tool-less `session.title` request
  is redacted deterministically without policy injection so title output is
  preserved.
- Configured **local-directory** installs need a root `index.js` (plus `rpc.js`/
  `tui.js` when used); the resolver does not read a local package's `main`/
  `exports`. Installing by package name uses the published exports normally.
- The global shell backstop also covers the user's own terminals and background
  shells. Dynamic targets that need shell expansion are skipped deterministically.
- Default safety evaluation now includes `patch` and `read`; output sanitization
  uses `shell` instead of `bash` (the legacy alias still works).
- Session deny-rule sync replaces the host ruleset non-atomically; it is defense
  in depth, not the authoritative guard.

See [CHANGELOG.md](CHANGELOG.md) for the complete 2.0.0 release notes.

## Documentation

- [**Configuration**](docs/configuration.md) — Configuration hierarchy, all option tables, complete example, and minimal config presets
- [**How It Works**](docs/how-it-works.md) — Hook pipeline, detection engine, LLM integration, customizing prompts, action modes, and permission system integration
- [**Built-in Tools**](docs/tools.md) — All 7 tools documented: `security_help`, `security_dashboard`, `security_report`, `security_audit`, `security_evaluate`, `security_config`, `security_rules`
- [**Detection Patterns**](docs/detection-patterns.md) — Full pattern tables for all categories: API keys, credentials, private keys, Docker, Kubernetes, cloud providers, and PII
- [**Use Cases**](docs/use-cases.md) — 8 example configurations covering solo dev, team projects, CI/CD, SSH-only mode, enterprise, and more
- [**Audit Logging & Environment Sanitization**](docs/audit-logging.md) — Log format, rotation, querying, and environment variable sanitization
- [**Changelog**](CHANGELOG.md) — Release notes and the 2.0.0 upgrade/breaking-change summary

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/toreuyar/opencode-warden).

### Development

```bash
# Install dependencies
bun install

# Run tests
bun test

# Type check
bun run typecheck

# Build
bun run build
```

### Adding Detection Patterns

To add a new built-in pattern:

1. Choose the appropriate file in `src/detection/patterns/`
2. Add a `DetectionPattern` object with:
   - Unique `id`
   - Descriptive `name`
   - Appropriate `category`
   - Precise `pattern` regex (avoid overly broad patterns)
   - `redact` function that replaces matched text
   - `confidence` level (`low`, `medium`, or `high`)
3. Add tests in `tests/detection-patterns.test.ts`
4. Run `bun test` to verify no regressions

## License

MIT License

Copyright (c) 2026 Töre Çağrı Uyar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
