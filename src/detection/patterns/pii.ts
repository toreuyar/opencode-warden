import type { DetectionPattern } from "../../types.js"

function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, "")
  let sum = 0
  let alternate = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10)
    if (alternate) {
      n *= 2
      if (n > 9) n -= 9
    }
    sum += n
    alternate = !alternate
  }
  return sum % 10 === 0
}

export const piiPatterns: DetectionPattern[] = [
  {
    id: "pii-email",
    name: "Email Address",
    category: "pii-email",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi,
    redact: () => "[REDACTED]",
    confidence: "medium",
  },
  {
    id: "pii-us-phone",
    name: "US Phone Number",
    category: "pii-phone",
    pattern: /(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)/g,
    redact: () => "[REDACTED]",
    confidence: "medium",
  },
  {
    id: "pii-international-phone",
    name: "International Phone Number",
    category: "pii-phone",
    pattern: /\+[1-9]\d{1,2}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}/g,
    redact: () => "[REDACTED]",
    confidence: "low",
  },
  {
    id: "pii-ssn",
    name: "US Social Security Number",
    category: "pii-ssn",
    pattern: /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "pii-credit-card",
    name: "Credit Card Number",
    category: "pii-credit-card",
    pattern: /(?<!\d)\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)/g,
    redact: (m) => {
      // Validate with Luhn check
      if (!luhnCheck(m)) return m // Not a valid card, don't redact
      return "[REDACTED]"
    },
    confidence: "high",
  },
  {
    id: "pii-ipv4",
    name: "IPv4 Address",
    category: "pii-ip-address",
    pattern: /(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)/g,
    redact: (m) => {
      // Don't redact common non-sensitive IPs
      if (
        m === "127.0.0.1" ||
        m === "0.0.0.0" ||
        m.startsWith("192.168.") ||
        m.startsWith("10.") ||
        m === "255.255.255.255" ||
        m === "255.255.255.0"
      ) {
        return m
      }
      return "[REDACTED]"
    },
    confidence: "low",
  },
]

// Export luhnCheck for testing
export { luhnCheck }
