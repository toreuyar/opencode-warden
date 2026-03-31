import type { DetectionPattern } from "../../types.js"

export const dockerPatterns: DetectionPattern[] = [
  {
    id: "docker-swarm-token",
    name: "Docker Swarm Join Token",
    category: "docker",
    pattern: /SWMTKN-1-[a-z0-9]{49,}-[a-z0-9]{25,}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "docker-registry-auth",
    name: "Docker Registry Auth",
    category: "docker",
    pattern: /(?<="auth"\s*:\s*")[A-Za-z0-9+/=]{20,}(?=")/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "docker-run-env-secret",
    name: "Docker Run Inline Secret",
    category: "docker",
    pattern: /(?<=docker\s+(?:run|exec|create)\s+.*(?:-e|--env)\s+(?:[A-Z_]*(?:SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL|AUTH)[A-Z_]*)=)[^\s]+/gi,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "docker-build-arg-secret",
    name: "Docker Build Arg Secret",
    category: "docker",
    pattern: /(?<=--build-arg\s+(?:[A-Z_]*(?:SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL|AUTH)[A-Z_]*)=)[^\s]+/gi,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "docker-compose-env-secret",
    name: "Docker Compose Environment Secret",
    category: "docker",
    pattern: /(?<=[A-Z_](?:SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL|AUTH)[A-Z_]*\s*[=:]\s*)[^\s\n'"]{8,}/g,
    redact: () => "[REDACTED]",
    confidence: "low",
  },
]
