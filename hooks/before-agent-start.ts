/**
 * before_agent_start hook: inject ClawGuardian instructions into the system prompt.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { ClawGuardianConfig } from "../config.js";

/**
 * Build the ClawGuardian context to inject into the system prompt.
 */
function buildClawGuardianContext(cfg: ClawGuardianConfig): string {
  const lines: string[] = [];

  lines.push("<clawguardian>");
  lines.push(
    "ClawGuardian is active. It monitors tool calls for sensitive data and destructive commands.",
  );

  // Explain the agent-confirm mechanism
  lines.push("");
  lines.push("If a tool call is blocked with a message asking you to confirm:");
  lines.push('- Add `"_clawguardian_confirm": true` to the tool parameters and retry');
  lines.push("- Only confirm if you understand the risk and the action is intentional");
  lines.push("- For secrets/PII, confirmation will still redact the sensitive data");
  lines.push("");
  lines.push("Actions:");
  lines.push("- block: Tool call rejected entirely");
  lines.push("- redact: Sensitive data replaced with [REDACTED]");
  lines.push("- confirm: User approval required (exec/bash tools only)");
  lines.push("- agent-confirm: You must retry with _clawguardian_confirm: true");
  lines.push("- warn/log: Allowed with logging");

  // List what's being monitored
  const monitored: string[] = [];
  if (cfg.secrets.enabled) {
    monitored.push("API keys, tokens, credentials");
  }
  if (cfg.pii.enabled) {
    const piiTypes: string[] = [];
    if (cfg.pii.categories.ssn) {
      piiTypes.push("SSN");
    }
    if (cfg.pii.categories.creditCard) {
      piiTypes.push("credit cards");
    }
    if (cfg.pii.categories.email) {
      piiTypes.push("emails");
    }
    if (cfg.pii.categories.phone) {
      piiTypes.push("phone numbers");
    }
    if (piiTypes.length > 0) {
      monitored.push(`PII (${piiTypes.join(", ")})`);
    }
  }
  if (cfg.destructive.enabled) {
    monitored.push("destructive commands (rm -rf, git reset, DROP TABLE, etc.)");
  }

  if (monitored.length > 0) {
    lines.push("");
    lines.push(`Monitoring: ${monitored.join("; ")}`);
  }

  lines.push("</clawguardian>");

  return lines.join("\n");
}

export function registerBeforeAgentStartHook(api: OpenClawPluginApi, cfg: ClawGuardianConfig): void {
  // Only inject if there's something to monitor
  if (!cfg.secrets.enabled && !cfg.pii.enabled && !cfg.destructive.enabled) {
    return;
  }

  api.on(
    "before_agent_start",
    (_event, _ctx) => {
      const context = buildClawGuardianContext(cfg);
      return {
        prependContext: context,
      };
    },
    { priority: 50 }, // Lower priority so other plugins can add context first
  );
}
