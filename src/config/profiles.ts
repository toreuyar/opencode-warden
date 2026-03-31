import type { OperationalProfileValue } from "../types.js"

export interface BuiltinProfile {
  description: string
  patterns: string[]
}

export const BUILTIN_PROFILES: Record<string, BuiltinProfile> = {
  "log-review": {
    description:
      "Read-only log file inspection: tail, cat, less, head on /var/log/*, journalctl, dmesg",
    patterns: [
      "tail /var/log/*",
      "tail -f /var/log/*",
      "tail -n * /var/log/*",
      "tail * /var/log/auth.log",
      "cat /var/log/*",
      "cat /var/log/auth.log",
      "less /var/log/*",
      "head /var/log/*",
      "head -n * /var/log/*",
      "head * /var/log/auth.log",
      "journalctl *",
      "dmesg",
      "dmesg *",
    ],
  },

  "security-monitoring": {
    description:
      "Security tool read-only queries: CrowdSec decisions/alerts/bouncers/metrics/hub, fail2ban status, security log reading",
    patterns: [
      "cscli decisions list *",
      "cscli decisions list",
      "cscli alerts list *",
      "cscli alerts list",
      "cscli bouncers list",
      "cscli bouncers list *",
      "cscli metrics",
      "cscli metrics *",
      "cscli hub list",
      "cscli hub list *",
      "fail2ban-client status",
      "fail2ban-client status *",
      "cat /var/log/modsec*",
      "tail /var/log/modsec*",
      "cat /var/log/fail2ban*",
      "tail /var/log/fail2ban*",
      "cat /var/log/audit/*",
      "tail /var/log/audit/*",
      "crowdsec-cli decisions list *",
      "crowdsec-cli decisions list",
      "crowdsec-cli alerts list *",
      "crowdsec-cli alerts list",
      "crowdsec-cli bouncers list",
      "crowdsec-cli bouncers list *",
      "crowdsec-cli metrics",
      "crowdsec-cli metrics *",
      "crowdsec-cli hub list",
      "crowdsec-cli hub list *",
      "ufw status",
      "ufw status *",
    ],
  },

  "service-status": {
    description:
      "Service status inspection: systemctl status/is-active/is-enabled/list-units/list-timers, docker ps/inspect/logs, nginx -t/-T",
    patterns: [
      "systemctl status *",
      "systemctl status",
      "systemctl is-active *",
      "systemctl is-enabled *",
      "systemctl list-units *",
      "systemctl list-units",
      "systemctl list-timers *",
      "systemctl list-timers",
      "service * status",
      "docker ps",
      "docker ps *",
      "docker inspect *",
      "docker logs *",
      "docker compose ps",
      "docker compose ps *",
      "nginx -t",
      "nginx -T",
    ],
  },

  "system-health": {
    description:
      "System health monitoring: df, free, uptime, top snapshot, iostat, vmstat, ss, lsof, w, who, last",
    patterns: [
      "df *",
      "df",
      "free *",
      "free",
      "uptime",
      "top -bn1",
      "top -bn1 *",
      "iostat *",
      "iostat",
      "vmstat *",
      "vmstat",
      "ss *",
      "ss",
      "lsof -i *",
      "lsof -i",
      "w",
      "who",
      "last",
      "last *",
    ],
  },
}

/**
 * Resolve all allowed patterns by merging user-defined patterns
 * with patterns from enabled operational profiles.
 */
export function resolveAllowedPatterns(
  allowedOperations: string[],
  operationalProfiles: Record<string, OperationalProfileValue>,
): string[] {
  const patterns = new Set<string>(allowedOperations)

  for (const [name, value] of Object.entries(operationalProfiles)) {
    const enabled =
      typeof value === "boolean" ? value : value.enabled
    if (!enabled) continue

    const builtin = BUILTIN_PROFILES[name]
    if (builtin) {
      for (const p of builtin.patterns) {
        patterns.add(p)
      }
    }

    if (typeof value === "object" && value.additionalPatterns) {
      for (const p of value.additionalPatterns) {
        patterns.add(p)
      }
    }
  }

  return Array.from(patterns)
}

/**
 * Get descriptions of active profiles for LLM context injection.
 */
export function getActiveProfileDescriptions(
  operationalProfiles: Record<string, OperationalProfileValue>,
): Array<{ name: string; description: string }> {
  const active: Array<{ name: string; description: string }> = []

  for (const [name, value] of Object.entries(operationalProfiles)) {
    const enabled =
      typeof value === "boolean" ? value : value.enabled
    if (!enabled) continue

    const builtin = BUILTIN_PROFILES[name]
    if (builtin) {
      active.push({ name, description: builtin.description })
    }
  }

  return active
}
