# How It Works

[← Back to README](../README.md)

Warden **2.2.0** runs as an OpenCode V2 plugin through `@opencode/plugin`
(`Plugin.define` + `setup(ctx)`). It registers domain hooks rather than the legacy
single-hook API. The supported OpenCode **host** floor is **2.0.18**; that is a
host requirement, not the Warden version. Typed per-call `Tool.Error` vetoes
require host **2.0.29+**.

| OpenCode host | Warden plugin | Notes |
|---|---|---|
| OpenCode 1.x (V1 plugin API) | **1.3.0**, pinned | Warden 2.x is not compatible with a V1 host. Use `opencode-warden@1.3.0`. |
| OpenCode 2.0.0–2.0.17 | **2.2.0** | Below the declared 2.0.18 floor; not verified. Loads with a warning and keeps protections installed. |
| OpenCode 2.0.18–2.0.28 | **2.2.0** | Declared supported floor. Historical bounded 2.0.18 runtime validation used Warden 2.0.0. Blocks through the older untyped per-call rejection path; typed `Tool.Error` vetoes require 2.0.29+. |
| OpenCode 2.0.29+ | **2.2.0** | Supported. Typed veto mapping is source/package-verified; not runtime-probed on a 2.0.29 or 2.1.4 binary. |

OpenCode 2.x is the target line, but not every 2.x host is certified.

### Runtime verification

The 2.2.0 changes have unit/mocked-test and build coverage plus a bounded live
llama-swap queue/disconnect probe. There is no new host probe or live-provider
accuracy evaluation. The following host results belong to 2.0.0.

Bounded validation of the built 2.0.0 on **OpenCode 2.0.18** (the declared floor,
using local mocks and loaded through a root `index.js`) passed config precedence and inline fallback, invalid-config
lockdown, V2 `path`/`shell`/`subagent` blocking, write/read/error redaction,
outbound tool-result redaction and policy injection, shell backstop,
evaluator/sanitizer outage blocking in `warn`, explicit `llm.enabled: false`
deterministic mode, `session.update({ permissions })` preservation and
application, server RPC/SSE notification delivery, compaction policy plus
redaction with a valid summary, and a title/generate replay: tool-less title
sent `[REDACTED]` with no policy and persisted `Replay Title`; generate sent
redacted text with policy and normal tools and returned `PROBE_DONE`. That run
exercised the untyped per-call rejection path, which is what 2.0.18–2.0.28 use
for a blocked call.

The typed `Tool.Error` veto mapping introduced in `@opencode/plugin` 2.0.29 is
source/package-verified, not runtime-probed on a 2.0.29 or 2.1.4 binary. Live
rendered TUI toasts remain untested, and no external provider was used. A
bounded 2.0.18 secret-write replay passed with the structural tool-call-input
projection (exit 0, next request redacted, policy present); the raw pre-hook
input remains at rest and this is not a broad certification. Structured output
was redacted at runtime through the host-normalized content path; the
content-less structured fallback branch is unreachable on 2.0.18 and remains
unit-test only.

## Hook Pipeline

OpenCode invokes hooks in registration order. The pipeline below shows the
security order Warden is designed around, not a guaranteed host ordering API.

```
session.prompt (opt-in)
    → scan prompt text + attachment metadata
    → throw to abort prompt admission
        ↓
tool.execute.before (authoritative per-call gate)
    → lazy session deny-rule sync (defense in depth)
    → blockedTools / excludedTools / sshOnlyMode gates
    → blocked and write-protected file targets
    → regex deep-scan + redaction of arguments
    → LLM safety evaluation (unless already evaluated)
    → throw a per-call veto (typed on 2.0.29+; untyped rejection on 2.0.18–2.0.28) to block
        ↓
shell.create.before (shell creation only)
    → global path backstop for agent and user shells
    → environment variable stripping/redaction
        ↓
permission.evaluate (when the host asserts a permission)
    → deterministic tool/path/resource checks
    → LLM safety evaluation
    → deny / ask / allow + denial message
        ↓
[ tool executes ]
        ↓
tool.execute.after
    → regex + optional LLM sanitization of content/title/metadata
    → error-message and cause sanitization
    → audit log + sanitized TUI/RPC notification
        ↓
session.context (before each primary provider dispatch)
    → append per-request security policy system part
    → remove blocked tools from request definitions
    → redact supported outbound text and tool-result text
        ↓
session.generate (auxiliary full-context request)
    → same policy, blocked-tool removal, and outbound redaction as context
        ↓
session.title (tool-less title request)
    → deterministic outbound redaction; no policy injection
        ↓
session.compaction (before a summary request)
    → same deterministic policy + outbound scanning
```

`tool.transform` adds Warden's seven custom tools and removes configured
blocked tools from the registered tool list. OpenCode places plugin tools in
**Code Mode** by default, so the `security_*` tools are invoked through `execute`
(for example `return await tools.security_help({})`) rather than appearing in the
native provider tool list; `blockedTools` removal still operates on the effective
registry. Session lifecycle events (`session.created`, `session.deleted`,
`session.permissions`) reset per-session state, invalidate the deny-rule cache,
and drop deleted sessions.

Hooks other than `tool.execute.before` have no typed failure channel in the
supported host API (on 2.0.18–2.0.28, `execute.before` also uses the untyped
rejection path). When they throw, request preparation or shell creation
aborts; this is still fail-closed, but it surfaces as a generic session or
runtime error rather than a clean per-call veto.

### `session.prompt` — opt-in prompt admission

When `scanUserPrompts` is `true` and redaction is enabled, Warden scans the
prompt text and **attachment metadata**: file URI (except inline `data:`
content), name, description, agent name, skill id/name, and mention text.
Attachment file contents are deliberately not read. A detection throws, which
prevents the prompt from being persisted or sent to the model. The OpenCode TUI
shows a generic `"Session error"`; the detailed reason is written to the audit
and diagnostic logs. This UX limitation is why the feature is opt-in.

### `tool.execute.before` — authoritative per-call gate

This is the primary pre-execution guard. It:

1. Lazily synchronizes session deny rules for the current session.
2. Enforces `blockedTools`, `excludedTools`, and `sshOnlyMode` (alias-aware).
3. Rejects adjacent top-level shell commands/pipelines joined by `;` or a
   command-ending newline using a Bash AST, before any model request.
4. Checks every file target: V2 `path` (with legacy `filePath` fallback), every
   `patchText` add/update/delete/move target, and shell redirections/reads.
5. Deep-scans arguments for secrets and redacts in place, subject to
   `redactionEnabled`, `redactOnWrite`, and `redactionExemptPaths`.
   Rechecks the static shell gate if redaction changed the command.
6. If enabled, runs the command-only complexity precheck for eligible shell
   syntax before file-content or direct safety evaluation. `simplify` vetoes;
   `continue` requires full evaluation. A precheck failure also vetoes.
7. Runs the LLM safety evaluator when the tool is eligible, with permission-call
   deduplication except when a precheck continuation requires a fresh verdict.
8. Throws a per-call veto on a block verdict or evaluator failure. On
   `@opencode/plugin` 2.0.29+ this maps to a typed `Tool.Error`; on 2.0.18–2.0.28
   it aborts the call through the older untyped rejection path.

Skipping a call here is a security decision only for `llm.enabled: false`
(deterministic-only mode). An enabled evaluator that is missing for a configured
tool also blocks.

### `shell.create.before` — global shell backstop

The sequence gate and complexity precheck above are agent-tool checks, not user
terminal checks. The static gate does not traverse nested constructs or reject
conditional lists/background jobs merely for their composition. Model precheck
selection is broader, but remains optional. Neither gate rewrites commands.

Every shell creation goes through a deterministic path backstop, not only agent
tool calls. Blocked paths and write-protected paths therefore also apply to the
**user's own terminals and background shells**. The backstop resolves relative
`cwd` against the workspace, checks SSH/SCP/rsync/rclone remote paths, and
skips dynamic targets such as unexpanded `$VAR` or backtick substitutions
because resolving them would require executing the shell. Environment variable
stripping and value redaction run immediately after the path check.

### `permission.evaluate` — host permission decisions

When OpenCode asks Warden to evaluate a permission, Warden runs deterministic
tool/path/resource checks first, then optionally the LLM. It writes back
`deny`, `ask`, or `allow` and a denial message. A denied or failed evaluation is
not recorded in the deduplication set, so a later attempt can be re-evaluated.
Deduplication saves LLM calls; it is not a security boundary, and the input
sanitizer remains authoritative.

Warden also translates exactly representable policy into session-scoped deny
rules: literal blocked tools, literal absolute blocked paths, and literal
absolute write-protected paths. Globs, relative/`~` paths, `host:` entries,
wildcards, and shell path policy are omitted because OpenCode's permission
matcher is not Warden's glob matcher. `session.update({ permissions })` replaces
the host ruleset and has no compare-and-set; Warden re-reads, merges, and
re-reads before writing, which narrows but does not eliminate a concurrent
update race. A failed sync never changes an allow/deny decision.

### `tool.execute.after` — output and error sanitization

Warden scans textual output, title, metadata, and error message/cause. Regex
redaction runs first, followed by the optional LLM pass. If the LLM is enabled
and the sanitizer is unavailable for a tool in its configured list, output is
withheld in `redact` and `warn` modes rather than released raw. `pass` is an
explicit detection-only debugging mode: it logs detections and performs no
redaction.

Per-path exemptions and the global `redactionEnabled` switch skip redaction for
that call while leaving file blocking, write-protection, and safety evaluation
active. Each skipped call is recorded with its reason.

Structured results are sanitized through the host-normalized content string. On
2.0.18 a tool that returned only `output` was normalized to JSON text and
redacted at runtime. The adapter's content-less `structuredFallback` branch is
unreachable under that normalization, so it remains unit-test-only defense.

### `session.context`, `session.generate`, `session.title`, and `session.compaction` — outbound DLP

`session.context` runs before each primary provider dispatch. It appends the
security policy as a request-local system part, removes blocked tools from that
request's definitions, and redacts supported outbound system/message/tool-result
text. `session.generate` reuses the full session context and applies the same
policy append, blocked-tool restrictions, and deterministic redaction.
`session.title` is tool-less: Warden redacts its system/messages but deliberately
does not append the policy, preserving title output. `session.compaction`
applies the same deterministic policy and scanning to the native summary
request.

These mutations are **ephemeral**: they apply to the request projection, not to
stored conversation history. Tool-call IDs/names, message metadata, and
`providerMetadata` are preserved for pairing and replay. Historical tool-call
input strings are structurally redacted in the projection with argument keys,
ids/names, and object/array shape preserved. File/media identifiers and
provider-signed or encrypted text are scanned read-only; when a detection would
require rewriting one of those structures, Warden aborts the request instead of
corrupting provider pairing or a signature. Unsupported shapes and scanner
failures also abort preparation.

**Secret-bearing writes leave raw input at rest.** Input redaction protects the
file that `write`/`edit`/`patch` produces, but OpenCode persists the original
tool-call input before `tool.execute.before` runs. The next primary dispatch
structurally redacts detected strings in that historical input for the provider
request, so the secret is not forwarded. Warden does not rewrite the session
database, so the raw input remains at rest; projection redaction is not at-rest
scrubbing. The exemption switches skip that projection redaction and allow the
secret through; they are not a secure fix. A bounded 2.0.18 replay passed with
this structural projection (exit 0, next request redacted, policy present); it
does not certify 2.0.18 or 2.1.4.

A bounded 2.0.18 local-mock replay verified the auxiliary surfaces: the
tool-less title request had `systemHasPolicy:false`, sent `[REDACTED]` instead of
the raw key, persisted `Replay Title`, and exited 0; the public generate request
had `systemHasPolicy:true` with normal tools, sent redacted text, and returned
`PROBE_DONE`. No external provider, 2.1.4 binary, or live rendered TUI was used.

Attachment bodies and binary/media payloads are not scanned as text. Coverage
depends on the host exposing supported text and tool-result fields.

### Notifications

Notifications are delivered through an event-only RPC contract
(`opencode-warden.notifications`). Events contain a closed kind plus optional
bounded tool id/count — never paths, arguments, output, explanations, or raw
audit text. The optional TUI companion renders fixed copy. Registration or
delivery failure is non-blocking, and a slow or absent TUI cannot delay hook
installation or a security decision. Server RPC/SSE registration and real event
delivery passed on 2.0.18; **live rendered TUI toasts were not tested**. Audit
and diagnostic files remain the durable record, subject to the short-lived CLI
flush caveat in [Audit Logging](audit-logging.md).

## Detection Engine

The detection engine uses a two-pass approach:

**Pass 1: Regex (fast, deterministic)**

- 66 defined built-in patterns, 65 active by default across 11 category
  switches (API keys, credentials, private keys, Docker, Kubernetes, cloud, and
  PII groups)
- Custom user-defined patterns
- Deep recursive scanning of nested objects and arrays (up to 10 levels)
- Overlapping match resolution (longer matches take priority; equal lengths use
  confidence)
- Confidence levels (low, medium, high)
- Conditional redaction for PII: credit cards use a Luhn checksum, and IPv4
  detection excludes common private ranges

**Pass 2: LLM (context-aware, catches novel patterns)**

- Optional second pass using an OpenAI-compatible endpoint
- Receives tool name, arguments, and related context
- Catches secrets regex misses, such as base64-encoded credentials and custom
  token formats
- Fails closed: an unavailable, timed-out, or invalid LLM withholds output or
  blocks the operation when the LLM is enabled

`pii-ip-address` is disabled by default because of false positives. The pattern
id is `pii-ipv4`; use `disabledPatterns` to disable individual patterns and
`categories` to disable a whole group.

## LLM Integration

Warden uses any **OpenAI-compatible** chat completions API, including Ollama,
llama.cpp, vLLM, LM Studio, OpenAI, Azure OpenAI, and compatible gateways.

### Safety Evaluator

Before sending an LLM request, the provider chain acquires a slot in the shared
endpoint queue. Queue wait has its own timeout; the overall evaluation deadline
covers all model stages, waiting, retries, and fallback. Retry delays release
capacity, and transient errors may trigger exponential backoff or server
`Retry-After` pauses. Cancellation removes waiting requests and aborts HTTP;
interrupted inference pauses admission to give the backend time to recover.
Results and accumulated conversation exchanges remain bound to the original
caller. See [provider scheduling configuration](configuration.md#provider-concurrency-queueing-and-retries)
for defaults and the lifecycle-based hook cancellation limitation.

The safety evaluator analyzes tool calls across **12 risk dimensions**:

| Dimension | Examples |
|---|---|
| **Exfiltration** | `curl -X POST` with file data, `git push` to unknown remotes |
| **Destruction** | `rm -rf /`, `mkfs`, `DROP DATABASE`, `kubectl delete namespace` |
| **Service Disruption** | `systemctl stop`, `docker kill`, `kill -9` |
| **System Tampering** | Modifying `/etc/passwd`, `/etc/sudoers`, SSH config |
| **Excessive Collection** | `nmap`, `find / -name`, `ps aux`, `getent passwd` |
| **Privilege Escalation** | `sudo`, `chown root`, `chmod 4755`, `setcap` |
| **Persistence** | `crontab -e`, creating systemd services, adding SSH keys |
| **Resource Abuse** | Fork bombs, infinite loops, cryptocurrency miners |
| **Network Manipulation** | `iptables`, DNS configuration, firewall rule changes |
| **Supply Chain** | `curl | bash`, `pip install` from unknown sources |
| **Remote Execution** | Remote host blast radius, transfer destinations, forwarding and recovery access |
| **Indirect Execution** | Effects of written scripts or other files subsequently executed |

Dimensions describe effects, not blanket bans on command names. Routine sudo,
monitoring, and service maintenance are distinguished from prohibited effects.

Each eligible call receives a risk level (`none`, `low`, `medium`, `high`,
`critical`) and a recommendation (`allow`, `warn`, `block`) based on configured
thresholds. A model `block`/`warn` verdict is a floor and is not downgraded by a
contradictory lower risk level. An evaluator infrastructure failure is marked
separately and blocks regardless of action mode.

### Context Management

The evaluator can retain a sliding window of conversation history:

- Up to 5 user+assistant pairs (configurable)
- Bounded by 16,000 characters (configurable)
- Optionally only exchanges that produced detections
- Reset per session

## Customizing Prompts

The components below support configurable prompts. The optional shell
complexity precheck has a fixed prompt and strict structural verdict schema. Set
`systemPrompt` to replace system-level instructions and `promptTemplate` to
replace the user-level prompt format.

| Component | Config path | Template variables |
|---|---|---|
| Safety Evaluator | `llm.safetyEvaluator.systemPrompt` / `promptTemplate` | `{{toolName}}`, `{{args}}` |
| Output Sanitizer | `llm.outputSanitizer.systemPrompt` / `promptTemplate` | `{{toolName}}`, `{{output}}`, `{{context}}` |
| Output Triage | `llm.outputTriage.systemPrompt` / `promptTemplate` | `{{toolName}}`, `{{args}}` |
| Text Triage | `llm.outputTextTriage.systemPrompt` / `promptTemplate` | `{{toolName}}`, `{{args}}`, `{{output}}` |
| Indirect Execution | `indirectExecution.systemPrompt` / `promptTemplate` | `{{command}}`, `{{filePath}}`, `{{fileContent}}`, `{{fileOrigin}}` |

Template variables use `{{variableName}}` syntax and are replaced at runtime.
An empty or omitted field uses the built-in default prompt.

The 2.1.0 defaults use compact, self-contained instructions with explicit rule
precedence and JSON contracts for small evaluator models. Custom overrides do
not inherit these default instructions. Shorter prompts have unit/mocked
coverage, not a claim of equal accuracy across all models.

**Example** — custom safety evaluator prompt for a CI/CD environment:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "llama3",
    "safetyEvaluator": {
      "systemPrompt": "You are a CI/CD security evaluator. Only block commands that could leak secrets or destroy production data. All build and test commands are safe.",
      "promptTemplate": "Evaluate this CI/CD tool call:\n\nTOOL: {{toolName}}\nARGS:\n{{args}}\n\nRespond with JSON: {\"safe\": true/false, \"riskLevel\": \"none/low/medium/high/critical\", \"riskDimensions\": [], \"explanation\": \"\", \"suggestedAlternative\": \"\", \"recommendation\": \"allow/warn/block\"}"
    }
  }
}
```

## Action Modes

### Input Safety (`safetyEvaluator.actionMode`)

```
                ┌──────────────────────────────┐
                │   Tool call detected as      │
                │   potentially dangerous      │
                └──────────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
         ┌────────┐     ┌────────────┐    ┌────────┐
         │ "block"│     │"permission"│    │ "warn" │
         └───┬────┘     └─────┬──────┘    └───┬────┘
             │                │               │
             ▼                ▼               ▼
        Auto-block      Deny / ask /      Warning;
        (per-call veto) allow via host    genuine risk
                        permission        may proceed
```

| Mode | Behavior |
|---|---|
| `"block"` | Throw a per-call veto (typed `Tool.Error` on 2.0.29+; untyped rejection on 2.0.18–2.0.28); the AI sees the block reason |
| `"permission"` | Deny on block, ask on warn, allow on allow; fall back to block if the permission hook does not fire |
| `"warn"` | Show a warning and allow a genuine risky call to proceed |

In every mode, an **evaluator outage blocks** when the LLM is enabled. `warn`
covers a genuine model verdict, not an infrastructure failure. If `llm.enabled`
is `false`, no LLM call is attempted and deterministic-only mode runs without
outage blocking.

### Output Sanitization (`outputSanitizer.actionMode`)

| Mode | Behavior |
|---|---|
| `"redact"` | Auto-redact secrets; notifications are rate-limited |
| `"warn"` | Redact and always show a detailed notification, bypassing the rate limiter |
| `"pass"` | Do not redact; log detections only (explicit debugging mode) |

For `redact` and `warn`, an enabled-but-unavailable sanitizer withholds output
rather than releasing it unsanitized.

## Permission System Integration

When `safetyEvaluator.actionMode` is `"permission"`, Warden integrates with
OpenCode's permission evaluation:

1. **`permission.evaluate` fires** when the host asserts a permission:
   - Warden runs deterministic checks and, when eligible, the LLM evaluation.
   - At or above `blockThreshold`, Warden denies; the denial message is carried
     back to the host.
   - At or above `warnThreshold`, Warden asks so the user can decide with the
     risk context.
   - Otherwise it allows.
   - The call id is recorded to avoid duplicate evaluation.
2. **`tool.execute.before` still runs for every tool call:**
   - It skips LLM re-evaluation when the same call id was already evaluated.
   - If permission evaluation did not fire, the input sanitizer's own gate
     remains authoritative.

This provides coverage for both host-prompted and auto-allowed tool calls. The
observed host order can run `tool.execute.before` before `permission.evaluate`,
which may cause duplicate evaluation but does not create a bypass. Session deny
rules are a second layer only; the authoritative guards are the input
sanitizer, shell backstop, permission handler, and output sanitizer.
