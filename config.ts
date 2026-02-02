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
    ssn: boolean; // high severity
    creditCard: boolean; // high severity
    email: boolean; // medium severity
    phone: boolean; // medium severity
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

// Legacy type aliases for backward compatibility
export type ClawGuardianMode = SeverityAction;
export type DestructiveAction = SeverityAction;
export type ClawGuardianFilters = ClawGuardianSecretsConfig["categories"] & {
  pii: ClawGuardianPiiConfig["categories"] & { enabled: boolean };
};
export type ClawGuardianPiiFilters = ClawGuardianPiiConfig["categories"] & { enabled: boolean };

const DEFAULT_SECRETS: ClawGuardianSecretsConfig = {
  enabled: true,
  action: "redact",
  severityActions: {
    critical: "block", // Private keys
    high: "redact", // API keys, tokens, cloud credentials
    medium: "redact",
    low: "warn",
  },
  categories: {
    apiKeys: true,
    cloudCredentials: true,
    privateKeys: true,
    tokens: true,
  },
};

const DEFAULT_PII: ClawGuardianPiiConfig = {
  enabled: true,
  action: "redact",
  severityActions: {
    critical: "block",
    high: "redact", // SSN, credit card
    medium: "warn", // Email, phone
    low: "warn",
  },
  categories: {
    ssn: true, // high severity
    creditCard: true, // high severity
    email: false, // medium severity (off by default - false positives)
    phone: false, // medium severity (off by default - false positives)
  },
};

const DEFAULT_DESTRUCTIVE: ClawGuardianDestructiveConfig = {
  enabled: true,
  action: "confirm",
  severityActions: {
    critical: "block", // rm -rf /, DROP DATABASE, dd
    high: "confirm", // rm -rf, git reset --hard, sudo
    medium: "confirm", // kill, git checkout
    low: "warn", // git branch -d
  },
  categories: {
    fileDelete: true,
    gitDestructive: true,
    sqlDestructive: true,
    systemDestructive: true,
    processKill: true,
    networkDestructive: true,
    privilegeEscalation: true,
  },
};

const DEFAULT_ALLOWLIST: ClawGuardianAllowlist = {};

const DEFAULT_LOGGING: ClawGuardianLogging = {
  logDetections: true,
  logLevel: "warn",
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseSeverityAction(value: unknown, fallback: SeverityAction): SeverityAction {
  if (
    value === "block" ||
    value === "redact" ||
    value === "confirm" ||
    value === "agent-confirm" ||
    value === "warn" ||
    value === "log"
  ) {
    return value;
  }
  return fallback;
}

function parseSeverityActions(value: unknown, defaults: SeverityActions): SeverityActions {
  if (!isPlainObject(value)) {
    return defaults;
  }
  return {
    critical: parseSeverityAction(value.critical, defaults.critical),
    high: parseSeverityAction(value.high, defaults.high),
    medium: parseSeverityAction(value.medium, defaults.medium),
    low: parseSeverityAction(value.low, defaults.low),
  };
}

function parseSecrets(value: unknown): ClawGuardianSecretsConfig {
  if (!isPlainObject(value)) {
    return DEFAULT_SECRETS;
  }
  return {
    enabled: value.enabled !== false,
    action: parseSeverityAction(value.action, "redact"),
    severityActions: parseSeverityActions(value.severityActions, DEFAULT_SECRETS.severityActions),
    categories: isPlainObject(value.categories)
      ? {
          apiKeys: value.categories.apiKeys !== false,
          cloudCredentials: value.categories.cloudCredentials !== false,
          privateKeys: value.categories.privateKeys !== false,
          tokens: value.categories.tokens !== false,
        }
      : DEFAULT_SECRETS.categories,
  };
}

function parsePii(value: unknown): ClawGuardianPiiConfig {
  if (!isPlainObject(value)) {
    return DEFAULT_PII;
  }
  return {
    enabled: value.enabled !== false,
    action: parseSeverityAction(value.action, "redact"),
    severityActions: parseSeverityActions(value.severityActions, DEFAULT_PII.severityActions),
    categories: isPlainObject(value.categories)
      ? {
          ssn: value.categories.ssn !== false,
          creditCard: value.categories.creditCard !== false,
          email: value.categories.email === true,
          phone: value.categories.phone === true,
        }
      : DEFAULT_PII.categories,
  };
}

function parseDestructive(value: unknown): ClawGuardianDestructiveConfig {
  if (!isPlainObject(value)) {
    return DEFAULT_DESTRUCTIVE;
  }
  return {
    enabled: value.enabled !== false,
    action: parseSeverityAction(value.action, "confirm"),
    severityActions: parseSeverityActions(
      value.severityActions,
      DEFAULT_DESTRUCTIVE.severityActions,
    ),
    categories: isPlainObject(value.categories)
      ? {
          fileDelete: value.categories.fileDelete !== false,
          gitDestructive: value.categories.gitDestructive !== false,
          sqlDestructive: value.categories.sqlDestructive !== false,
          systemDestructive: value.categories.systemDestructive !== false,
          processKill: value.categories.processKill !== false,
          networkDestructive: value.categories.networkDestructive !== false,
          privilegeEscalation: value.categories.privilegeEscalation !== false,
        }
      : DEFAULT_DESTRUCTIVE.categories,
  };
}

function parseCustomPatterns(value: unknown): ClawGuardianCustomPattern[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((item): item is Record<string, unknown> => isPlainObject(item))
    .map((item): ClawGuardianCustomPattern => {
      const name = typeof item.name === "string" ? item.name : "custom";
      const pattern = typeof item.pattern === "string" ? item.pattern : "";
      const severity: Severity | undefined =
        item.severity === "critical" ||
        item.severity === "high" ||
        item.severity === "medium" ||
        item.severity === "low"
          ? item.severity
          : undefined;
      const action: SeverityAction | undefined = parseSeverityAction(
        item.action,
        undefined as unknown as SeverityAction,
      );
      return { name, pattern, severity, action: action || undefined };
    })
    .filter((p) => p.pattern.length > 0);
}

function parseAllowlist(value: unknown): ClawGuardianAllowlist {
  if (!isPlainObject(value)) {
    return DEFAULT_ALLOWLIST;
  }
  const tools = Array.isArray(value.tools)
    ? (value.tools as unknown[]).filter((t): t is string => typeof t === "string")
    : undefined;
  const patterns = Array.isArray(value.patterns)
    ? (value.patterns as unknown[]).filter((p): p is string => typeof p === "string")
    : undefined;
  const sessions = Array.isArray(value.sessions)
    ? (value.sessions as unknown[]).filter((s): s is string => typeof s === "string")
    : undefined;
  return { tools, patterns, sessions };
}

function parseLogging(value: unknown): ClawGuardianLogging {
  if (!isPlainObject(value)) {
    return DEFAULT_LOGGING;
  }
  const logLevel =
    value.logLevel === "debug" ||
    value.logLevel === "info" ||
    value.logLevel === "warn" ||
    value.logLevel === "error"
      ? value.logLevel
      : "warn";
  return {
    logDetections: value.logDetections !== false,
    logLevel,
  };
}

/**
 * Parse and validate plugin config with defaults.
 */
export function parseClawGuardianConfig(raw: unknown): ClawGuardianConfig {
  if (!raw || !isPlainObject(raw)) {
    return {
      filterToolInputs: true,
      filterToolOutputs: true,
      secrets: DEFAULT_SECRETS,
      pii: DEFAULT_PII,
      destructive: DEFAULT_DESTRUCTIVE,
      customPatterns: [],
      allowlist: DEFAULT_ALLOWLIST,
      logging: DEFAULT_LOGGING,
    };
  }

  const cfg = raw as unknown as Record<string, unknown>;

  return {
    filterToolInputs: cfg.filterToolInputs !== false,
    filterToolOutputs: cfg.filterToolOutputs !== false,
    secrets: parseSecrets(cfg.secrets),
    pii: parsePii(cfg.pii),
    destructive: parseDestructive(cfg.destructive),
    customPatterns: parseCustomPatterns(cfg.customPatterns),
    allowlist: parseAllowlist(cfg.allowlist),
    logging: parseLogging(cfg.logging),
  };
}

/**
 * Get the action for a given severity level from a config section.
 */
export function getActionForSeverity(
  severity: Severity,
  config: { action: SeverityAction; severityActions: SeverityActions },
): SeverityAction {
  return config.severityActions[severity] ?? config.action;
}
