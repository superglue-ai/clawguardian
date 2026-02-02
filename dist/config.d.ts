/**
 * ClawGuardian plugin configuration types and validation.
 */
/**
 * Unified severity levels used across all detection types.
 */
export type Severity = "critical" | "high" | "medium" | "low";
/**
 * Actions that can be taken when something is detected.
 * - "block": Reject the tool call entirely
 * - "redact": Replace sensitive data with [REDACTED] (secrets/PII only)
 * - "confirm": Require user confirmation (exec/bash tools only, via OpenClaw approval flow)
 * - "agent-confirm": Block until agent retries with _clawguardian_confirm: true
 * - "warn": Log warning but allow execution
 * - "log": Silent logging only
 */
export type SeverityAction = "block" | "redact" | "confirm" | "agent-confirm" | "warn" | "log";
/**
 * Per-severity action configuration.
 */
export type SeverityActions = {
    critical: SeverityAction;
    high: SeverityAction;
    medium: SeverityAction;
    low: SeverityAction;
};
/**
 * Secrets detection config (API keys, tokens, cloud credentials, private keys).
 */
export type ClawGuardianSecretsConfig = {
    enabled: boolean;
    /** Default action for secrets */
    action: SeverityAction;
    /** Per-severity actions (all secrets are high severity by default) */
    severityActions: SeverityActions;
    /** Categories to detect */
    categories: {
        apiKeys: boolean;
        cloudCredentials: boolean;
        privateKeys: boolean;
        tokens: boolean;
    };
};
/**
 * PII detection config.
 */
export type ClawGuardianPiiConfig = {
    enabled: boolean;
    /** Default action for PII */
    action: SeverityAction;
    /** Per-severity actions */
    severityActions: SeverityActions;
    /** Categories to detect */
    categories: {
        ssn: boolean;
        creditCard: boolean;
        email: boolean;
        phone: boolean;
    };
};
/**
 * Destructive command detection config.
 * Based on SafeExec patterns (https://github.com/agentify-sh/safeexec).
 */
export type ClawGuardianDestructiveConfig = {
    enabled: boolean;
    /** Default action for destructive commands */
    action: SeverityAction;
    /** Per-severity actions */
    severityActions: SeverityActions;
    /** Categories to detect */
    categories: {
        fileDelete: boolean;
        gitDestructive: boolean;
        sqlDestructive: boolean;
        systemDestructive: boolean;
        processKill: boolean;
        networkDestructive: boolean;
        privilegeEscalation: boolean;
    };
};
export type ClawGuardianCustomPattern = {
    name: string;
    pattern: string;
    severity?: Severity;
    action?: SeverityAction;
};
export type ClawGuardianAllowlist = {
    tools?: string[];
    patterns?: string[];
    sessions?: string[];
};
export type ClawGuardianLogging = {
    logDetections: boolean;
    logLevel: "debug" | "info" | "warn" | "error";
};
export type ClawGuardianConfig = {
    filterToolInputs: boolean;
    filterToolOutputs: boolean;
    secrets: ClawGuardianSecretsConfig;
    pii: ClawGuardianPiiConfig;
    destructive: ClawGuardianDestructiveConfig;
    customPatterns: ClawGuardianCustomPattern[];
    allowlist: ClawGuardianAllowlist;
    logging: ClawGuardianLogging;
};
export type ClawGuardianMode = SeverityAction;
export type DestructiveAction = SeverityAction;
export type ClawGuardianFilters = ClawGuardianSecretsConfig["categories"] & {
    pii: ClawGuardianPiiConfig["categories"] & {
        enabled: boolean;
    };
};
export type ClawGuardianPiiFilters = ClawGuardianPiiConfig["categories"] & {
    enabled: boolean;
};
/**
 * Parse and validate plugin config with defaults.
 */
export declare function parseClawGuardianConfig(raw: unknown): ClawGuardianConfig;
/**
 * Get the action for a given severity level from a config section.
 */
export declare function getActionForSeverity(severity: Severity, config: {
    action: SeverityAction;
    severityActions: SeverityActions;
}): SeverityAction;
//# sourceMappingURL=config.d.ts.map