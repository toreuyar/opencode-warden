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

## Features

- **74 built-in detection patterns** across 11 categories — API keys, credentials, private keys, PII, cloud provider secrets, Docker, Kubernetes, and more
- **LLM-powered safety evaluation** across 10 risk dimensions (exfiltration, destruction, privilege escalation, and more)
- **LLM-enhanced output sanitization** — catches context-dependent secrets that regex alone misses
- **File path blocking** with glob patterns — prevents access to `.env`, `*.pem`, `*.key`, kubeconfig, tfstate, and other sensitive files
- **Environment variable sanitization** — strips secrets from the shell environment before they reach tool calls
- **SSH-only mode** — monitor only remote commands (ssh, scp, sftp, rsync, rclone) while bypassing all local operations
- **7 built-in tools** — dashboard, reports, audit queries, dry-run evaluation, config view, and rule management
- **Three-layer rule architecture** — builtin, user-managed, and AI-managed detection rules
- **Customizable prompts** — replace any LLM prompt via config using `{{variableName}}` templates
- **Zero-config operation** — works out of the box with sensible defaults, no LLM required
- **Comprehensive audit logging** — JSON-line log files with rotation, verbosity levels, and session statistics
- **Configurable action modes** — auto-block, user-prompted permission, or warn-only for both input safety and output sanitization

## Installation

### Prerequisites

- [OpenCode](https://opencode.ai) v0.1.0 or later
- [Bun](https://bun.sh) runtime (OpenCode uses Bun for plugins)

### Install from npm (Recommended)

Add `opencode-warden` to the `plugin` array in your OpenCode configuration:

**Global** (`~/.config/opencode/opencode.json`) — applies to all projects:

```json
{
  "plugin": ["opencode-warden"]
}
```

**Project-level** (`./opencode.json`) — applies to a single project:

```json
{
  "plugin": ["opencode-warden"]
}
```

OpenCode automatically installs the package via Bun when it starts.

### Install from Source

If you prefer to run from source (for development or customization):

```bash
git clone https://github.com/toreuyar/opencode-warden.git
cd opencode-warden
bun install
```

Then register the plugin by adding its **absolute path** to `opencode.json`:

```json
{
  "plugin": [
    "/absolute/path/to/opencode-warden"
  ]
}
```

> **Note**: The path must be absolute (e.g., `/home/user/opencode-warden` on Linux, `/Users/user/opencode-warden` on macOS). A wrong or non-existent path will cause OpenCode to hang on startup.

### Alternative: Plugin Directory

You can also copy or symlink the plugin source into OpenCode's plugin directories:

- **Global**: `~/.config/opencode/plugins/`
- **Project-level**: `.opencode/plugins/`

Files placed in these directories are loaded automatically.

## Quick Start

Warden works with **zero configuration**. Once installed, it immediately:

1. Blocks access to sensitive files (`.env`, `*.pem`, `*.key`, etc.)
2. Scans and redacts secrets in tool inputs and outputs using 74 regex patterns
3. Sanitizes environment variables before they reach shell commands
4. Logs all security events to `.opencode/warden/audit.log`
5. Provides 7 built-in tools for real-time visibility and rule management
6. Shows toast notifications when secrets are detected or blocked

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

## Documentation

- [**Configuration**](docs/configuration.md) — Configuration hierarchy, all option tables, complete example, and minimal config presets
- [**How It Works**](docs/how-it-works.md) — Hook pipeline, detection engine, LLM integration, customizing prompts, action modes, and permission system integration
- [**Built-in Tools**](docs/tools.md) — All 7 tools documented: `security_help`, `security_dashboard`, `security_report`, `security_audit`, `security_evaluate`, `security_config`, `security_rules`
- [**Detection Patterns**](docs/detection-patterns.md) — Full pattern tables for all categories: API keys, credentials, private keys, Docker, Kubernetes, cloud providers, and PII
- [**Use Cases**](docs/use-cases.md) — 8 example configurations covering solo dev, team projects, CI/CD, SSH-only mode, enterprise, and more
- [**Audit Logging & Environment Sanitization**](docs/audit-logging.md) — Log format, rotation, querying, and environment variable sanitization

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
3. Add tests in `tests/patterns.test.ts`
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
