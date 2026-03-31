# Example Use Cases

[← Back to README](../README.md)

## 1. Solo Developer — Regex-Only Protection

You're a solo developer who wants basic secret protection without running an LLM. No config file needed:

```json
{}
```

What happens:
- 74 regex patterns scan every tool input and output
- `.env`, `*.pem`, `*.key`, and 20+ other sensitive file patterns are blocked
- Environment variables with secret-like names are stripped
- Audit log captures all events
- Toast notifications appear when secrets are detected

## 2. Team Project — Custom Patterns and Blocked Files

Your team has internal API key formats and additional sensitive files:

**`.opencode/opencode-warden.json`:**

```json
{
  "customPatterns": [
    {
      "id": "acme-api-key",
      "name": "ACME Internal API Key",
      "category": "api-keys",
      "pattern": "acme_sk_[A-Za-z0-9]{40}",
      "redactTemplate": "acme_sk_[REDACTED]",
      "confidence": "high"
    }
  ],
  "blockedFilePaths": [
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/secrets/**",
    "**/internal-config.yaml"
  ],
  "whitelistedPaths": [
    "**/.env.example",
    "**/secrets/README.md"
  ]
}
```

## 3. Security-Conscious Workflow — LLM Safety with User Prompts

You want the AI to ask for permission before running risky commands, with a risk assessment shown alongside the prompt:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "llama3",
    "safetyEvaluator": {
      "actionMode": "permission",
      "blockThreshold": "critical",
      "warnThreshold": "low"
    }
  }
}
```

What happens:
- When the AI tries to run `bash` with `rm -rf important_dir/`:
  - LLM evaluates it as `critical` risk → auto-denied, no prompt shown
- When the AI tries to run `bash` with `npm install some-unknown-package`:
  - LLM evaluates it as `medium` risk → OpenCode shows a permission prompt, and a toast shows the risk assessment so you understand WHY you're being asked
- When the AI runs `git status`:
  - Bypassed command → no evaluation, proceeds normally

## 4. CI/CD Auditing Mode — Warn but Don't Block

In a CI/CD environment, you want full visibility without disrupting the pipeline:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://internal-llm:8080/v1",
    "model": "safety-model",
    "safetyEvaluator": {
      "actionMode": "warn"
    },
    "outputSanitizer": {
      "actionMode": "warn"
    }
  },
  "audit": {
    "verbosity": "verbose"
  }
}
```

What happens:
- All tool calls are evaluated for safety risks, but none are blocked
- All output secrets are redacted, with detailed category information in every toast
- Verbose audit logging captures every event including clean passes
- Review the audit log after the run to identify potential issues

## 5. Debugging Secret Detection — Pass Mode

You're testing your custom patterns and want to see what gets detected without any redaction:

```json
{
  "llm": {
    "enabled": false,
    "outputSanitizer": {
      "actionMode": "pass"
    }
  }
}
```

What happens:
- Regex scans still run and detections are logged
- No secrets are redacted in output — you see the raw text
- Toast notifications tell you what was detected and where
- Useful for tuning `disabledPatterns` and `customPatterns`

## 6. Remote Server Administration — SSH-Only Mode

You use OpenCode primarily to administer remote servers and want security monitoring only for remote operations:

```json
{
  "sshOnlyMode": true
}
```

What happens:
- The AI can freely read, edit, and write local files - no scanning or blocking
- When the AI runs `ssh user@server "cat /etc/config"` - the command and output are fully scanned and redacted
- When the AI runs `scp user@server:/home/user/.env ./local/` - blocked (remote `.env` access)
- When the AI runs `rsync -avz user@server:/data/ ./backup/` - remote file paths are checked
- Local commands like `ls`, `git status`, `npm test` bypass all security checks
- Environment variable sanitization is skipped entirely

## 7. Enterprise — Azure OpenAI with Full Lockdown

Corporate environment with Azure OpenAI, strict blocking, and comprehensive auditing:

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "https://corp-resource.openai.azure.com/openai/deployments/gpt-4o",
    "model": "gpt-4o",
    "apiKey": "",
    "headers": {
      "api-key": "your-azure-api-key"
    },
    "completionsPath": "/chat/completions?api-version=2024-10-21",
    "healthCheckPath": "/health",
    "safetyEvaluator": {
      "actionMode": "block",
      "blockThreshold": "medium",
      "warnThreshold": "low",
      "tools": ["bash", "write", "edit", "webfetch", "read"]
    },
    "outputSanitizer": {
      "actionMode": "warn",
      "tools": ["read", "bash", "grep", "write", "edit"]
    }
  },
  "categories": {
    "pii-ip-address": true
  },
  "audit": {
    "enabled": true,
    "verbosity": "verbose",
    "maxFileSize": 52428800,
    "maxFiles": 10
  },
  "env": {
    "stripPatterns": [
      "*_SECRET",
      "*_SECRET_*",
      "*_TOKEN",
      "*_TOKEN_*",
      "*_PASSWORD",
      "*_PASSWORD_*",
      "*_KEY",
      "*_API_KEY",
      "*_API_KEY_*",
      "*_PRIVATE_KEY",
      "CORP_*",
      "INTERNAL_*"
    ]
  }
}
```

## 8. Global Developer Settings

Settings that apply to all your projects — your LLM endpoint, personal preferences:

**`~/.config/opencode/opencode-warden.json`:**

```json
{
  "llm": {
    "enabled": true,
    "baseUrl": "http://localhost:11434/v1",
    "model": "llama3",
    "safetyEvaluator": {
      "actionMode": "permission"
    }
  },
  "categories": {
    "pii-phone": false,
    "pii-ssn": false
  },
  "notifications": true,
  "audit": {
    "verbosity": "normal"
  }
}
```

Then in a specific project that needs stricter settings:

**`.opencode/opencode-warden.json`:**

```json
{
  "llm": {
    "safetyEvaluator": {
      "blockThreshold": "medium"
    }
  },
  "blockedFilePaths": [
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/production-secrets/**"
  ]
}
```

The project config merges into the global config. The project inherits the global LLM endpoint and permission mode, but overrides the block threshold to be more strict.
