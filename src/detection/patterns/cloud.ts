import type { DetectionPattern } from "../../types.js"

export const cloudPatterns: DetectionPattern[] = [
  // Azure
  {
    id: "azure-connection-string",
    name: "Azure Storage Connection String",
    category: "cloud",
    pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,};/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "azure-sas-token",
    name: "Azure SAS Token",
    category: "cloud",
    pattern: /[?&](?:sv|sig)=[^&\s'"]{10,}(?:&[a-z]{2,3}=[^&\s'"]+){2,}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "azure-ad-client-secret",
    name: "Azure AD Client Secret",
    category: "cloud",
    pattern: /(?<=(?:AZURE_CLIENT_SECRET|client_secret|clientSecret)\s*[=:]\s*['"]?)[A-Za-z0-9~._-]{30,}/g,
    redact: () => "[REDACTED]",
    confidence: "medium",
  },

  // Terraform
  {
    id: "terraform-state-sensitive",
    name: "Terraform State Sensitive Value",
    category: "cloud",
    pattern: /(?<="sensitive":\s*true,\s*"value":\s*")[^"]+/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "terraform-var-secret",
    name: "Terraform Variable Secret",
    category: "cloud",
    pattern: /(?<=TF_VAR_(?:[a-z_]*(?:secret|password|token|key)[a-z_]*)=)[^\s]+/gi,
    redact: () => "[REDACTED]",
    confidence: "high",
  },

  // HashiCorp Vault
  {
    id: "vault-token-hvs",
    name: "Vault Token (hvs)",
    category: "cloud",
    pattern: /hvs\.[A-Za-z0-9_-]{24,}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "vault-token-s",
    name: "Vault Token (s.)",
    category: "cloud",
    pattern: /(?<=(?:VAULT_TOKEN|X-Vault-Token)\s*[=:]\s*['"]?)s\.[A-Za-z0-9]{24,}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },

  // Pulumi
  {
    id: "pulumi-passphrase",
    name: "Pulumi Config Passphrase",
    category: "cloud",
    pattern: /(?<=PULUMI_CONFIG_PASSPHRASE[=:]\s*['"]?)[^\s'"]+/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },

  // Heroku
  {
    id: "heroku-api-key",
    name: "Heroku API Key",
    category: "cloud",
    pattern: /(?<=(?:HEROKU_API_KEY|heroku_api_key)\s*[=:]\s*['"]?)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },

  // Vercel
  {
    id: "vercel-token",
    name: "Vercel Token",
    category: "cloud",
    pattern: /(?<=(?:VERCEL_TOKEN|vercel_token)\s*[=:]\s*['"]?)[A-Za-z0-9]{24,}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },

  // Supabase
  {
    id: "supabase-service-role-key",
    name: "Supabase Service Role Key",
    category: "cloud",
    pattern: /(?<=(?:SUPABASE_SERVICE_ROLE_KEY|supabase_service_role_key|service_role)\s*[=:]\s*['"]?)eyJ[A-Za-z0-9_-]{100,}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "supabase-anon-key",
    name: "Supabase Anon Key",
    category: "cloud",
    pattern: /(?<=(?:SUPABASE_ANON_KEY|supabase_anon_key|anon_key)\s*[=:]\s*['"]?)eyJ[A-Za-z0-9_-]{100,}/g,
    redact: () => "[REDACTED]",
    confidence: "medium",
  },

  // Cloudflare
  {
    id: "cloudflare-api-token",
    name: "Cloudflare API Token",
    category: "cloud",
    pattern: /(?<=(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN)\s*[=:]\s*['"]?)[A-Za-z0-9_-]{40,}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "cloudflare-global-api-key",
    name: "Cloudflare Global API Key",
    category: "cloud",
    pattern: /(?<=(?:CF_API_KEY|CLOUDFLARE_API_KEY)\s*[=:]\s*['"]?)[0-9a-f]{37}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },

  // DigitalOcean
  {
    id: "digitalocean-pat",
    name: "DigitalOcean Personal Access Token",
    category: "cloud",
    pattern: /dop_v1_[a-f0-9]{64}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
]
