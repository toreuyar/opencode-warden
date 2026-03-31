import { describe, test, expect } from "bun:test"
import { apiKeyPatterns } from "../src/detection/patterns/api-keys.js"
import { credentialPatterns } from "../src/detection/patterns/credentials.js"
import { privateKeyPatterns } from "../src/detection/patterns/private-keys.js"
import { dockerPatterns } from "../src/detection/patterns/docker.js"
import { kubernetesPatterns } from "../src/detection/patterns/kubernetes.js"
import { cloudPatterns } from "../src/detection/patterns/cloud.js"
import { piiPatterns, luhnCheck } from "../src/detection/patterns/pii.js"
import type { DetectionPattern } from "../src/types.js"

function testPattern(pattern: DetectionPattern, input: string, shouldMatch: boolean) {
  const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags)
  const match = regex.exec(input)
  if (shouldMatch) {
    expect(match).not.toBeNull()
    if (match) {
      const redacted = pattern.redact(match[0])
      expect(redacted).not.toBe(match[0])
    }
  } else {
    // Either no match or match equals redacted (like non-sensitive IPs)
    if (match) {
      const redacted = pattern.redact(match[0])
      expect(redacted).toBe(match[0])
    }
  }
}

// ─── API Key Patterns ───

describe("API Key Patterns", () => {
  test("OpenAI API Key (sk-proj-)", () => {
    const p = apiKeyPatterns.find((p) => p.id === "openai-api-key")!
    testPattern(p, "my key is sk-proj-abc123def456ghi789jkl012mno345pqr678stu", true)
    testPattern(p, "no key here", false)
  })

  test("Anthropic API Key", () => {
    const p = apiKeyPatterns.find((p) => p.id === "anthropic-api-key")!
    testPattern(p, "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxx", true)
  })

  test("AWS Access Key", () => {
    const p = apiKeyPatterns.find((p) => p.id === "aws-access-key")!
    testPattern(p, "AKIAIOSFODNN7EXAMPLE", true)
    testPattern(p, "AKIA1234567890ABCDEF", true)
    testPattern(p, "notAKIA1234567890", false)
  })

  test("GitHub PAT", () => {
    const p = apiKeyPatterns.find((p) => p.id === "github-pat")!
    testPattern(p, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn", true)
  })

  test("GitHub Fine-Grained PAT", () => {
    const p = apiKeyPatterns.find((p) => p.id === "github-fine-grained-pat")!
    testPattern(p, "github_pat_11ABCDEF_abcdefghijklmnopqrstuvwxyz", true)
  })

  test("Slack Token", () => {
    const p = apiKeyPatterns.find((p) => p.id === "slack-token")!
    testPattern(p, "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", true)
  })

  test("Stripe Secret Key", () => {
    const p = apiKeyPatterns.find((p) => p.id === "stripe-secret-key")!
    testPattern(p, "sk_live_51HhBkZ2eZvKYlo2CWl3h4s6j", true)
    testPattern(p, "sk_test_51HhBkZ2eZvKYlo2CWl3h4s6j", true)
  })

  test("JWT Token", () => {
    const p = apiKeyPatterns.find((p) => p.id === "jwt-token")!
    testPattern(
      p,
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      true,
    )
  })

  test("SendGrid API Key", () => {
    const p = apiKeyPatterns.find((p) => p.id === "sendgrid-api-key")!
    testPattern(p, "SG.abcdef1234567890abcdef12.abcdef1234567890abcdef12", true)
  })

  test("NPM Token", () => {
    const p = apiKeyPatterns.find((p) => p.id === "npm-token")!
    testPattern(p, "npm_abcdef1234567890abcdef1234567890abcdef", true)
  })

  test("GCP API Key", () => {
    const p = apiKeyPatterns.find((p) => p.id === "gcp-api-key")!
    testPattern(p, "AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", true)
  })
})

// ─── Credential Patterns ───

describe("Credential Patterns", () => {
  test("Password in URL", () => {
    const p = credentialPatterns.find((p) => p.id === "password-in-url")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    const match = regex.exec("https://admin:s3cretP4ss@database.example.com/db")
    expect(match).not.toBeNull()
    if (match) {
      const redacted = p.redact(match[0])
      expect(redacted).toBe("[REDACTED]")
      expect(redacted).not.toContain("s3cretP4ss")
    }
  })

  test("MongoDB Connection String", () => {
    const p = credentialPatterns.find((p) => p.id === "mongodb-connection-string")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    const match = regex.exec("mongodb+srv://admin:password123@cluster.example.com/mydb")
    expect(match).not.toBeNull()
    if (match) {
      const redacted = p.redact(match[0])
      expect(redacted).toBe("[REDACTED]")
      expect(redacted).not.toContain("password123")
    }
  })

  test("PostgreSQL Connection String", () => {
    const p = credentialPatterns.find((p) => p.id === "postgres-connection-string")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    const match = regex.exec("postgresql://user:secret@localhost:5432/mydb")
    expect(match).not.toBeNull()
    if (match) {
      const redacted = p.redact(match[0])
      expect(redacted).toBe("[REDACTED]")
    }
  })

  test("Redis Connection String", () => {
    const p = credentialPatterns.find((p) => p.id === "redis-connection-string")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    const match = regex.exec("redis://:mypassword@redis.example.com:6379")
    expect(match).not.toBeNull()
  })
})

// ─── Private Key Patterns ───

describe("Private Key Patterns", () => {
  test("RSA Private Key", () => {
    const p = privateKeyPatterns.find((p) => p.id === "rsa-private-key")!
    testPattern(
      p,
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...\n-----END RSA PRIVATE KEY-----",
      true,
    )
  })

  test("OpenSSH Private Key", () => {
    const p = privateKeyPatterns.find((p) => p.id === "openssh-private-key")!
    testPattern(
      p,
      "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r...\n-----END OPENSSH PRIVATE KEY-----",
      true,
    )
  })

  test("PGP Private Key", () => {
    const p = privateKeyPatterns.find((p) => p.id === "pgp-private-key")!
    testPattern(
      p,
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: 1\nmQGNBGN...\n-----END PGP PRIVATE KEY BLOCK-----",
      true,
    )
  })

  test("EC Private Key", () => {
    const p = privateKeyPatterns.find((p) => p.id === "ec-private-key")!
    testPattern(
      p,
      "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----",
      true,
    )
  })
})

// ─── Docker Patterns ───

describe("Docker Patterns", () => {
  test("Docker Swarm Token", () => {
    const p = dockerPatterns.find((p) => p.id === "docker-swarm-token")!
    testPattern(
      p,
      "SWMTKN-1-3pu6hszjas19xyp7ghgosyx9k8atbfcr8p2is99znpy26u2lkl-1awxwuwd3z9j1z3puu7rcgdbx",
      true,
    )
  })
})

// ─── Kubernetes Patterns ───

describe("Kubernetes Patterns", () => {
  test("Kubeconfig Client Key Data", () => {
    const p = kubernetesPatterns.find(
      (p) => p.id === "kubeconfig-client-key-data",
    )!
    const input = `client-key-data: ${Array(60).fill("A").join("")}`
    testPattern(p, input, true)
  })
})

// ─── Cloud Patterns ───

describe("Cloud Patterns", () => {
  test("Azure Storage Connection String", () => {
    const p = cloudPatterns.find((p) => p.id === "azure-connection-string")!
    const input =
      "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
    testPattern(p, input, true)
  })

  test("Vault Token (hvs)", () => {
    const p = cloudPatterns.find((p) => p.id === "vault-token-hvs")!
    testPattern(p, "hvs.CAESIOsIjVlq4a5SSCDxPwVah2U0M9oQ", true)
  })

  test("DigitalOcean PAT", () => {
    const p = cloudPatterns.find((p) => p.id === "digitalocean-pat")!
    testPattern(
      p,
      "dop_v1_" + Array(64).fill("a").join(""),
      true,
    )
  })
})

// ─── PII Patterns ───

describe("PII Patterns", () => {
  test("Email Address", () => {
    const p = piiPatterns.find((p) => p.id === "pii-email")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    const match = regex.exec("john.doe@example.com")
    expect(match).not.toBeNull()
    if (match) {
      const redacted = p.redact(match[0])
      expect(redacted).toBe("[REDACTED]")
    }
  })

  test("US Phone Number", () => {
    const p = piiPatterns.find((p) => p.id === "pii-us-phone")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    const match = regex.exec("Call me at 555-867-5309")
    expect(match).not.toBeNull()
    if (match) {
      const redacted = p.redact(match[0])
      expect(redacted).toBe("[REDACTED]")
    }
  })

  test("SSN", () => {
    const p = piiPatterns.find((p) => p.id === "pii-ssn")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    const match = regex.exec("SSN: 123-45-6789")
    expect(match).not.toBeNull()
    if (match) {
      const redacted = p.redact(match[0])
      expect(redacted).toBe("[REDACTED]")
    }
  })

  test("Credit Card (valid Luhn)", () => {
    const p = piiPatterns.find((p) => p.id === "pii-credit-card")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    // Valid Visa test card number
    const match = regex.exec("Card: 4111 1111 1111 1111")
    expect(match).not.toBeNull()
    if (match) {
      const redacted = p.redact(match[0])
      expect(redacted).toBe("[REDACTED]")
    }
  })

  test("Credit Card (invalid Luhn — no redaction)", () => {
    const p = piiPatterns.find((p) => p.id === "pii-credit-card")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    const match = regex.exec("1234 5678 9012 3456")
    if (match) {
      const redacted = p.redact(match[0])
      // Invalid Luhn should not be redacted
      expect(redacted).toBe(match[0])
    }
  })

  test("IPv4 — public IP is redacted", () => {
    const p = piiPatterns.find((p) => p.id === "pii-ipv4")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    const match = regex.exec("Server: 203.0.113.42")
    expect(match).not.toBeNull()
    if (match) {
      const redacted = p.redact(match[0])
      expect(redacted).toBe("[REDACTED]")
    }
  })

  test("IPv4 — localhost is NOT redacted", () => {
    const p = piiPatterns.find((p) => p.id === "pii-ipv4")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    const match = regex.exec("127.0.0.1")
    expect(match).not.toBeNull()
    if (match) {
      const redacted = p.redact(match[0])
      expect(redacted).toBe("127.0.0.1") // Not redacted
    }
  })

  test("IPv4 — private IP is NOT redacted", () => {
    const p = piiPatterns.find((p) => p.id === "pii-ipv4")!
    const regex = new RegExp(p.pattern.source, p.pattern.flags)
    const match = regex.exec("192.168.1.1")
    expect(match).not.toBeNull()
    if (match) {
      const redacted = p.redact(match[0])
      expect(redacted).toBe("192.168.1.1") // Not redacted
    }
  })

  test("Luhn check", () => {
    expect(luhnCheck("4111111111111111")).toBe(true)
    expect(luhnCheck("4111111111111112")).toBe(false)
    expect(luhnCheck("5500000000000004")).toBe(true)
  })
})
