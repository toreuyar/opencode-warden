# Detection Patterns

[← Back to README](../README.md)

Warden ships with 74 built-in detection patterns across 7 major categories. All patterns are active by default except `pii-ip-address`.

You can disable individual patterns by ID using `disabledPatterns`, disable entire categories using `categories`, or add your own patterns using `customPatterns`. See [Configuration](configuration.md) for details.

## API Keys (20 patterns)

| Pattern | Description |
|---|---|
| OpenAI (project) | `sk-proj-*` tokens |
| OpenAI (legacy) | `sk-*` tokens (40+ chars) |
| Anthropic | `sk-ant-*` tokens |
| AWS Access Key | `AKIA*` (20 chars) |
| AWS Secret Key | 40-char base64 strings near AWS context |
| GCP API Key | `AIza*` (39 chars) |
| GitHub PAT | `ghp_*` tokens |
| GitHub OAuth | `gho_*` tokens |
| GitHub Fine-grained | `github_pat_*` tokens |
| Slack | `xox[bpas]-*` tokens |
| Stripe Secret | `sk_live_*` / `sk_test_*` |
| Stripe Restricted | `rk_live_*` / `rk_test_*` |
| JWT | `eyJ*` base64-encoded tokens |
| Bearer Token | Generic `Bearer *` tokens |
| SendGrid | `SG.*` tokens |
| Twilio | `SK*` (32 chars) |
| NPM Token | `npm_*` tokens |
| PyPI Token | `pypi-*` tokens |
| Discord Bot | `Bot *` / long base64 tokens |
| Mailgun | `key-*` tokens |

## Credentials (7 patterns)

| Pattern | Description |
|---|---|
| Password in URL | `://user:password@host` |
| Password Assignment | `password=`, `passwd:`, `api_key:`, etc. |
| MongoDB URI | `mongodb+srv://` connection strings |
| PostgreSQL URI | `postgresql://` / `postgres://` with credentials |
| MySQL URI | `mysql://` connection strings |
| Redis URI | `redis://` connection strings |
| Generic Connection | Connection strings with embedded passwords |

## Private Keys (7 patterns)

RSA, OpenSSH, DSA, EC, generic PEM, encrypted PEM, and PGP private key blocks.

## Docker (4 patterns)

Swarm join tokens, registry auth, inline secrets in `docker run -e`, build arg secrets, and compose environment secrets.

## Kubernetes (6 patterns)

Secret data values, kubeconfig tokens, client key/cert data, Helm `--set` secrets, and service account tokens.

## Cloud Providers (14 patterns)

Azure connection strings, SAS tokens, AD client secrets, Terraform state secrets, variable secrets, HashiCorp Vault tokens, Pulumi config passphrase, Heroku, Vercel, Supabase, Cloudflare, and DigitalOcean tokens.

## PII (6 patterns)

| Pattern | Description |
|---|---|
| Email | Standard email addresses |
| US Phone | US phone number formats |
| International Phone | `+` prefixed numbers |
| SSN | US Social Security Numbers (with separator validation) |
| Credit Card | Major card formats with Luhn checksum validation |
| IP Address | IPv4 addresses (excludes common private ranges like 127.0.0.1, 192.168.*, 10.*) |

> **Note**: `pii-ip-address` is disabled by default due to high false-positive rates. Enable it if your workflow requires IP detection.
