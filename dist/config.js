/**
 * ClawGuardian plugin configuration types and validation.
 */
const DEFAULT_SECRETS = {
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
const DEFAULT_PII = {
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
const DEFAULT_DESTRUCTIVE = {
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
const DEFAULT_ALLOWLIST = {};
const DEFAULT_LOGGING = {
    logDetections: true,
    logLevel: "warn",
};
function isPlainObject(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function parseSeverityAction(value, fallback) {
    if (value === "block" ||
        value === "redact" ||
        value === "confirm" ||
        value === "agent-confirm" ||
        value === "warn" ||
        value === "log") {
        return value;
    }
    return fallback;
}
function parseSeverityActions(value, defaults) {
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
function parseSecrets(value) {
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
function parsePii(value) {
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
function parseDestructive(value) {
    if (!isPlainObject(value)) {
        return DEFAULT_DESTRUCTIVE;
    }
    return {
        enabled: value.enabled !== false,
        action: parseSeverityAction(value.action, "confirm"),
        severityActions: parseSeverityActions(value.severityActions, DEFAULT_DESTRUCTIVE.severityActions),
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
function parseCustomPatterns(value) {
    if (!Array.isArray(value)) {
        return [];
    }
    return value
        .filter((item) => isPlainObject(item))
        .map((item) => {
        const name = typeof item.name === "string" ? item.name : "custom";
        const pattern = typeof item.pattern === "string" ? item.pattern : "";
        const severity = item.severity === "critical" ||
            item.severity === "high" ||
            item.severity === "medium" ||
            item.severity === "low"
            ? item.severity
            : undefined;
        const action = parseSeverityAction(item.action, undefined);
        return { name, pattern, severity, action: action || undefined };
    })
        .filter((p) => p.pattern.length > 0);
}
function parseAllowlist(value) {
    if (!isPlainObject(value)) {
        return DEFAULT_ALLOWLIST;
    }
    const tools = Array.isArray(value.tools)
        ? value.tools.filter((t) => typeof t === "string")
        : undefined;
    const patterns = Array.isArray(value.patterns)
        ? value.patterns.filter((p) => typeof p === "string")
        : undefined;
    const sessions = Array.isArray(value.sessions)
        ? value.sessions.filter((s) => typeof s === "string")
        : undefined;
    return { tools, patterns, sessions };
}
function parseLogging(value) {
    if (!isPlainObject(value)) {
        return DEFAULT_LOGGING;
    }
    const logLevel = value.logLevel === "debug" ||
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
export function parseClawGuardianConfig(raw) {
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
    const cfg = raw;
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
export function getActionForSeverity(severity, config) {
    return config.severityActions[severity] ?? config.action;
}
//# sourceMappingURL=config.js.map