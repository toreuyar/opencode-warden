import type { DetectionPattern } from "../../types.js"

export const kubernetesPatterns: DetectionPattern[] = [
  {
    id: "k8s-secret-data-value",
    name: "Kubernetes Secret Data Value",
    category: "kubernetes",
    pattern: /(?<=data:\s*\n(?:\s+\w+:\s*[^\n]*\n)*\s+\w+:\s*)[A-Za-z0-9+/=]{20,}/g,
    redact: () => "[REDACTED]",
    confidence: "medium",
  },
  {
    id: "kubeconfig-token",
    name: "Kubeconfig Token",
    category: "kubernetes",
    pattern: /(?<=token:\s*)[A-Za-z0-9_.-]{20,}/g,
    redact: () => "[REDACTED]",
    confidence: "medium",
  },
  {
    id: "kubeconfig-client-key-data",
    name: "Kubeconfig Client Key Data",
    category: "kubernetes",
    pattern: /(?<=client-key-data:\s*)[A-Za-z0-9+/=\n]{50,}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "kubeconfig-client-cert-data",
    name: "Kubeconfig Client Certificate Data",
    category: "kubernetes",
    pattern: /(?<=client-certificate-data:\s*)[A-Za-z0-9+/=\n]{50,}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "helm-set-secret",
    name: "Helm Set Secret Value",
    category: "kubernetes",
    pattern: /(?<=helm\s+.*--set\s+(?:[a-zA-Z._]*(?:secret|password|token|key|credential|auth)[a-zA-Z._]*)=)[^\s,]+/gi,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
  {
    id: "k8s-service-account-token",
    name: "K8s Service Account Token",
    category: "kubernetes",
    pattern: /(?<=serviceAccountToken:\s*['"]?)[A-Za-z0-9_.-]{50,}/g,
    redact: () => "[REDACTED]",
    confidence: "high",
  },
]
