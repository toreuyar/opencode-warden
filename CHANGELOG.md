# Changelog

All notable user-facing changes to OpenCode Warden are recorded here. The
project follows [Semantic Versioning](https://semver.org/). Release notes for
versions before 2.0.0 are available in the git history and release tags.

## [2.2.0] — 2026-11-22

**Provider concurrency and resilient LLM requests.** Run parallel coding-agent
tool calls against a capacity-limited evaluator without sending them all to the
GPU at once. Warden queues calls across sessions, keeps results paired with
their callers, and remains fail-closed when evaluation cannot complete.

### Added

- Add cancellation-aware queue admission, backoff and HTTP requests, an overall
  evaluation deadline, endpoint-wide recovery pauses, and Retry-After support.
  Hook cancellation is lifecycle-based because V2 Promise hooks lack a per-tool
  AbortSignal; the custom evaluation tool uses the host's execution signal.
- Apply provider limits live across plugin reloads using stable ownership.
  Add process-wide queue metrics to the dashboard and correlated scheduling logs.
- Isolate concurrent streaming chat logs by request/attempt ID and per-attempt
  counters. Verify a bounded queued burst and disconnect/recovery against a
  live llama-swap server, without claiming GPU cancellation guarantees.
- Add process-wide, endpoint-scoped FIFO request limits across all LLM
  components and sessions, with bounded queues and separate admission timeouts.
- Add provider `requestPolicy.maxAttempts`, exponential backoff with jitter,
  configurable initial delay/cap, and retries for transient or invalid responses.
  Explicit attempt limits override legacy sanitizer retry counts.
- Report queue overload to the original caller while preserving fail-closed
  blocking/withholding and provider fallback.
- Bind accumulated conversation exchanges to individual requests so overlapping
  evaluations cannot pair a response with another call's prompt.

### Documentation and packaging

- Reorder the README for first-time visitors: project benefits and quick start
  first, then features and documentation; detailed installation, compatibility,
  runtime boundaries, and migration history remain available further down.
- Update V2 installation examples to the native `plugins` key; retain V1
  installation instructions and historical resolver/runtime notes.
- Add provider scheduling configuration, cancellation limitations, operational
  metrics, and the opt-in live concurrency probe to the documentation.
- Include the README's icon in the npm package.

### Upgrade notes

- Existing configs remain valid. Queue limits are opt-in (`concurrency: 0`
  by default); use `1` for a single-request llama-swap/llama.cpp endpoint.
- `maxAttempts` counts the first request: `1` disables retries and `5` allows
  four retries. When unset, legacy sanitizer retry counts retain their semantics.
- LLM evaluations now have a default **300,000 ms overall budget** covering
  queueing, inference, backoff, and fallback. Set `totalTimeoutMs` for slower
  evaluators. Configure a positive provider `timeout`; the unresolved `0`
  sentinel is not an unlimited inference timeout.
- Interrupted inference pauses the endpoint for **5,000 ms** by default.
  `recoveryDelayMs: 0` disables that pause. An HTTP disconnect is not proof that
  the GPU stopped immediately.
- Queues are shared by normalized completion URL within one process, including
  different model names using that URL. Separate OpenCode processes do not share
  capacity. Reload plugin configuration to apply changed limits without a
  process restart.
- The supported host floor remains **OpenCode 2.0.18**; typed tool vetoes require
  **2.0.29+**. OpenCode 1.x users must retain Warden **1.3.0**.

### Verification

- Typecheck, **1,198 tests**, build, and diff checks passed.
- A bounded live llama-swap / `Nemotron-3.5-Bolt-E4B` probe verified four queued
  calls through two chains, peak active requests one, and correct response
  markers. A follow-up succeeded after disconnecting an unfinished stream.
- Hook lifecycle cancellation was exercised with simulated host events. No new
  OpenCode host runtime probe or broad live-model accuracy suite was performed.
  Historical host validation below belongs to Warden 2.0.0.

## [2.1.0] — 2026-11-22

### Added

- **Deterministic shell sequence gate.** Rejects adjacent top-level simple
  commands or pipelines separated by `;` or a command-ending newline before
  model evaluation. The agent receives guidance to use separate shell calls.
  Runs in agent pre-execution, permission checks, and evaluator dry runs, even
  with the LLM disabled. Single pipelines, quoted text, comments, continuations,
  and heredoc data are distinguished from command separators. Conditional lists,
  background jobs, and nested constructs are outside this static rule.
- **Optional shell complexity precheck**, configured with
  `llm.safetyEvaluator.complexityPrecheck.enabled` (default `false`). Selected
  complex shell calls receive a stateless, command-only request through the
  safety evaluator's provider chain. A validated structural `simplify` verdict
  blocks the attempt; `continue` requires full safety evaluation and never
  approves execution. Invalid/unavailable results block even in warn mode.

### Changed

- **Leaner prompts for small models.** The five main system prompts are about
  48% shorter by character count than the preceding working versions. Defaults
  use direct rules, explicit precedence, fewer contrasting examples, and exact
  response formats. Request templates and evidence headings are also shorter.
- Clarified untrusted-data boundaries, current-output-only sanitizer findings,
  interpreter-aware file evaluation, and specific-rule precedence over routine
  maintenance examples. Decoded data is checked for disclosure and write effects
  even when it is not executed. Triage no longer treats build/test logs or
  process/service output as inherently safe.
- Removed the built-in `helloworld.sh` test-only block rule. Remote execution
  risk follows concrete effects rather than an undefined remote premium.
- Agent policy distinguishes bypass attempts from Warden-requested
  simplification retries.
- Added `sh-ast` as a runtime dependency, kept external in the Bun build so its
  packaged WASM remains loadable.
- Harness results identify `static-block` and `complexity-precheck` layers.
  Expected verdicts use `allow` while retaining legacy `pass` compatibility.
  T7.5 now contains real command-ending newlines.

### Upgrade notes

- The host floor remains **OpenCode 2.0.18**; typed tool vetoes require
  **2.0.29+**. OpenCode 1.x users must keep Warden **1.3.0**.
- Existing configuration remains valid. The static gate is active without a new
  setting, subject to existing tool exclusions and SSH-only scope. Split
  sequential agent commands and specify the working directory/environment on
  each call. User terminals retain the existing global shell backstop.
- The complexity precheck is off by default. It also stays off when the LLM or
  safety evaluator is explicitly disabled. It uses the safety evaluator's
  providers; its prompt and structural reason vocabulary are fixed.
- Custom system prompts/templates still override the corresponding defaults.
  Review overrides separately to benefit from the new prompt guidance.

### Verification

- Typecheck, 1,163 unit/mocked tests, build, and diff checks passed during
  preparation. Prompt reductions are not a live-model accuracy claim.
- No live-provider regression suite or new host runtime probe was performed for
  2.1.0. The bounded 2.0.18 host results below belong to the 2.0.0 release.

## [2.0.0] — 2026-10-24

Warden **2.0.0** is the plugin release that ports the project to OpenCode's V2
plugin API. It is not an OpenCode host version: the supported host floor is
**OpenCode 2.0.18** (`@opencode/plugin` peer `^2.0.18`; developed and
type-checked against the 2.1.4 SDK). Typed per-call `Tool.Error` vetoes require
host **2.0.29+**; 2.0.18–2.0.28 block through the older untyped per-call
rejection path.

### Compatibility

| OpenCode host | Warden plugin | Notes |
|---|---|---|
| OpenCode 1.x (V1 plugin API) | **1.3.0**, pinned exactly | Last Warden release for OpenCode 1.x; published with `@opencode-ai/plugin` `^1.2.0`. Warden 2.0.0 is not compatible with a V1 host. |
| OpenCode 2.0.0–2.0.17 | **2.0.0** | Below the declared 2.0.18 floor; **not verified**. Warden loads with a warning and keeps protections installed. |
| OpenCode 2.0.18–2.0.28 | **2.0.0** | **Declared supported floor**, bounded runtime-validated on 2.0.18 with local mocks. Blocking works through the older untyped per-call rejection path. Clean typed `Tool.Error` vetoes require 2.0.29+. |
| OpenCode 2.0.29+ | **2.0.0** | Supported. The typed veto mapping introduced in 2.0.29 is source/package-verified; **not runtime-probed on a 2.0.29 or 2.1.4 binary**. |

OpenCode 1.x users should install the exact V1-compatible release:

```json
{
  "plugin": ["opencode-warden@1.3.0"]
}
```

Do not use an unpinned `"opencode-warden"` entry on an OpenCode 1.x host: once
2.0.0 is the npm `latest` tag, that entry resolves to an incompatible plugin.
For 2.x hosts, pin `"opencode-warden@2.0.0"` (or intentionally track latest).

### Runtime validation (2.0.18)

Bounded, isolated validation of the built 2.0.0 ran on **OpenCode 2.0.18**
(the declared floor, using local mocks and loaded through a root `index.js`) and
passed: configuration precedence and
inline fallback; invalid-config lockdown with no provider dispatch; V2
`path`/`shell`/`subagent` blocking; write, read, and error-result redaction;
outbound tool-result redaction and policy injection; global shell backstop;
enabled evaluator and output-sanitizer outage blocking in `warn`; explicit
`llm.enabled: false` deterministic mode; `session.update({ permissions })`
preservation and application; server RPC/SSE notification delivery; and
compaction policy injection plus redaction with a valid summary.

The bounded run exercised the untyped per-call rejection path available on
2.0.18. The typed `Tool.Error` veto mapping was introduced in
`@opencode/plugin` 2.0.29 and is source/package-verified, not runtime-probed on a
2.0.29 or 2.1.4 binary. Live rendered TUI toasts
were not tested; only server RPC/SSE delivery was. A bounded 2.0.18 secret-write
replay passed with the structural tool-call-input projection: exit 0 /
`PROBE_DONE`, the file contained `[REDACTED]`, and the next request had
`rawHasDKey:false`, `historyHasDKey:false`, and the policy present. That replay
does not scrub at-rest input. A bounded 2.0.18 title/generate
replay also passed: the tool-less title request had no policy, sent
`[REDACTED]` instead of the raw key, and persisted `Replay Title` with exit 0;
the public generate request had the policy and normal tools, sent redacted text,
and returned `PROBE_DONE`. Structured output was redacted at runtime through the
host-normalized content path; the content-less structured fallback branch is
unreachable on 2.0.18 and remains unit-test only. These results are bounded
validation, not a certification of every host behavior.

### Added

- **V2 hook coverage** for `session.prompt`, `tool.execute.before`,
  `shell.create.before`, `permission.evaluate`, `tool.execute.after`,
  `session.context`, `session.generate`, `session.title`, and
  `session.compaction`, plus session lifecycle event subscriptions.
- **Outbound and compaction DLP.** Before provider dispatch, Warden appends the
  security policy as a per-request system part and redacts supported outbound
  system/message/tool-result text. `session.generate` receives the same policy,
  blocked-tool restrictions, and scanning as a primary request. `session.title`
  is tool-less: it receives deterministic redaction without policy injection,
  preserving title quality. Compaction requests receive the same deterministic
  treatment. Redaction applies to the request projection only; stored history is
  not rewritten.
- **Tool-surface enforcement.** Blocked tools are removed from request tool
  definitions and from the registered tool list through `tool.transform`,
  including tools added by the same transform. Custom Warden tools are
  registered through the V2 editor rather than the legacy tool map.
- **Global shell backstop.** Every shell creation, including user terminals and
  background shells, is checked against the blocked/write-protected path
  policy. Environment stripping and value redaction run in the same hook.
- **Prompt attachment-metadata scanning.** Opt-in prompt scanning now covers
  text plus file URI/name/description, agent/skill names, and mention text.
  Attachment file contents are not read. Blocking aborts prompt admission.
- **Session deny rules (defense in depth).** Literal blocked tools and literal
  absolute blocked/write-protected paths are translated into session-scoped
  deny rules where OpenCode can express them exactly.
- **TUI/RPC notifications.** Hook alerts use a strict event-only contract with a
  closed kind and bounded tool/count metadata. The optional TUI companion
  renders fixed copy. Delivery is UX-only and never changes enforcement.
- **Session lifecycle wiring** for `session.created`, `session.deleted`, and
  `session.permissions`, including deny-rule cache invalidation and session-state
  cleanup.

### Changed

- **Configuration failures are an active lockdown.** Invalid or unreadable
  configuration no longer risks a failed plugin setup. Warden installs
  deny-all/withhold-all hooks and keeps them active until the configuration is
  fixed and OpenCode is restarted.
- **Inline configuration is a fallback only.** `ctx.options` are used only when
  neither the global nor the project config file exists. Any present file wins,
  even if that file is invalid or unreadable.
- **LLM outages are strictly fail-closed.** When the LLM is enabled,
  an unreachable, misconfigured, timed-out, or invalid evaluator/sanitizer
  blocks the operation regardless of `actionMode` — including `warn` and
  `permission`. Only explicit `llm.enabled: false` runs deterministic-only
  without outage blocking.
- **Output error handling.** Tool output, title, metadata, error messages, and
  error causes are sanitized. If an enabled sanitizer is unavailable for a tool
  in its list, output is withheld in `redact`/`warn` modes rather than released
  raw. `pass` remains an explicit detection-only debugging mode.
- **V2 tool vocabulary.** Defaults and policy use `shell`, `subagent`, and
  `path`; `bash`, `task`, and `filePath` remain accepted aliases. `patch`
  inputs are checked through every `patchText` add/update/delete/move target.
- **Default tool coverage.** Safety evaluation now defaults to `shell`, `write`,
  `edit`, `patch`, `read`, and `webfetch`; output sanitization defaults to
  `read`, `shell`, and `grep`. `excludedTools` now defaults to `[]` because V2
  has no `list` tool.

### Breaking changes and upgrade notes

- **OpenCode 1.x users must stay on Warden 1.3.0.** Warden 2.0.0 uses the V2
  plugin API and will not work as a V1 replacement.
- The supported host floor on the 2.x line is **OpenCode 2.0.18**
  (`@opencode/plugin` peer `^2.0.18`; development/type-checking uses 2.1.4).
  Hosts on 2.0.0–2.0.17 are below the floor and emit a warning while keeping
  protections installed. Hosts on 2.0.18–2.0.28 are supported and emit a
  typed-veto advisory: Warden blocks through the older untyped per-call
  rejection path exercised on 2.0.18, and typed `Tool.Error` vetoes require
  2.0.29+. Warden never refuses setup for a version mismatch; a
  failed setup would leave the host unprotected. Bounded 2.0.18 validation
  passed the cases above, but this is not a claim that every 2.x host is
  certified.
- Configured **local-directory** installs must provide a root `index.js`
  (`server.*` also works) and, when used, root `rpc.js`/`tui.js`. The host
  resolver probes those names instead of reading the local package's `main`/
  `exports`; a package directory without them loads silently as a no-op.
  Installing by package name resolves the published exports normally.
- Remove any `"list"` entry from `excludedTools`; it is obsolete and no longer
  matches a V2 tool.
- If you depend on raw toast text, migrate to the `opencode-warden.notifications`
  RPC contract. Notification events do not carry paths, arguments, output, or
  explanations.
- Audit and diagnostic files remain the durable record. A missing or slow TUI
  companion does not delay setup and does not weaken enforcement.
- The global shell backstop intentionally affects user-created shells, not only
  agent tool calls. Dynamic shell targets (for example unexpanded `$VAR` or
  backtick substitutions) cannot be resolved without executing the shell and are
  skipped by the deterministic backstop.

### Security boundaries and limitations

- **Hook ordering:** OpenCode runs hooks in registration order and has no
  priority API. A later plugin can observe or mutate earlier results, so Warden
  cannot guarantee its mutations are final. Treat the host and all loaded
  plugins as trusted, and load Warden last where possible.
- **Ephemeral redaction:** outbound redaction on `session.context`,
  `session.generate`, `session.title`, and `session.compaction` does not rewrite
  stored history. Tool-call IDs/names, message metadata, and `providerMetadata`
  are preserved. Historical tool-call input strings are structurally redacted in
  the request projection with keys/ids/names/shape preserved. File/media
  identifiers and provider-signed/encrypted text are never rewritten; a required
  rewrite aborts the request instead of corrupting provider pairing or
  signatures.
- **Secret-bearing writes:** write-time redaction protects the file, but the
  host persists the original tool-call input before `tool.execute.before`.
  Warden structurally redacts detected strings in that historical input for the
  next provider request, so the secret is not forwarded. The raw input remains at
  rest in the session store: projection redaction is not at-rest scrubbing.
  Provider-signed/encrypted or unsupported input shapes abort instead. Setting
  `redactOnWrite: false` or adding `redactionExemptPaths` exempts the historical
  input and allows the secret through; it is not a secure fix. A bounded 2.0.18
  secret-write replay passed (exit 0, next request redacted, policy present);
  raw pre-hook input remains at rest and this is not a broad certification.
- **Auxiliary requests:** `session.generate` uses the same policy append,
  blocked-tool removal, and outbound redaction as a primary request. The
  tool-less `session.title` request is redacted deterministically but receives no
  policy injection, preserving title output. Both passed a bounded 2.0.18
  local-mock replay (title sent `[REDACTED]` and persisted `Replay Title`;
  generate sent redacted text and returned `PROBE_DONE`). No external provider,
  2.1.4 binary, or live rendered TUI was used.
- **Media and provider payloads:** attachment file contents and binary/media
  bodies are not scanned by the outbound sanitizer. Coverage depends on the
  host exposing supported text/tool-result fields; unsupported shapes fail
  closed for the request.
- **Session permission sync:** `session.update({ permissions })` replaces the
  host ruleset and has no compare-and-set. Warden re-reads, merges, and
  re-reads before writing, which narrows but does not eliminate a concurrent
  update race. These rules are never the primary guard. Preservation and
  application passed on 2.0.18; newer-host behavior is source-verified only.
- **Code Mode tools:** plugin tools default to OpenCode Code Mode, so Warden's
  seven `security_*` tools are invoked through `execute` (`tools.security_*`),
  not listed in the native provider tool list. `blockedTools` removal still
  applies to the effective registry. Native direct visibility is not claimed.
- **Notification classification:** on 2.0.18 a blocked file read was emitted as
  RPC `kind: "denied"` rather than `"blocked"` because legacy toast text matched
  the denial classifier first. This is UX-only and does not change enforcement.
- **Audit durability:** audit writes are buffered (1 second or 10 entries). A
  short-lived `opencode run --standalone` process that exits immediately can
  leave a 0-byte audit file even though enforcement ran; long-lived servers
  flush normally. Enforcement is unaffected.
- **Runtime verification:** bounded runtime validation was performed on
  OpenCode 2.0.18 (the declared floor) with the built plugin loaded through a
  root `index.js` and local mocks.
  `session.update({ permissions })`, server RPC/SSE notification delivery, and
  compaction policy/redaction passed there, along with the untyped per-call
  block path. The typed `Tool.Error` veto mapping introduced in
  `@opencode/plugin` 2.0.29 (and the 2.1.4 hook shapes) is source/package-verified,
  not runtime-probed on a 2.0.29 or 2.1.4 binary.
  Live rendered TUI toasts remain untested. Structured output passed through the
  host-normalized content path; the content-less fallback branch is unit-test
  only.

### Documentation

- Added this changelog, an upgrade guide in the README, and refreshed the hook
  pipeline, audit/environment, detection-pattern, and use-case documentation for
  the V2 architecture.
