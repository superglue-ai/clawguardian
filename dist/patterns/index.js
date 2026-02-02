/**
 * Pattern registry: aggregates patterns by category for ClawGuardian.
 */
import { API_KEY_PATTERNS } from "./api-keys.js";
import { CLOUD_CREDENTIAL_PATTERNS } from "./cloud-credentials.js";
import { getPiiPatterns } from "./pii.js";
import { TOKEN_PATTERNS } from "./tokens.js";
export { API_KEY_PATTERNS } from "./api-keys.js";
export { CLOUD_CREDENTIAL_PATTERNS } from "./cloud-credentials.js";
export { TOKEN_PATTERNS } from "./tokens.js";
export { getPiiPatterns, PII_SSN, PII_SSN_NO_DASHES, PII_CREDIT_CARD, PII_PHONE, PII_EMAIL } from "./pii.js";
/**
 * Build all active regex patterns from config.
 */
export function buildPatterns(cfg) {
    const list = [];
    // Secrets patterns
    if (cfg.secrets.enabled) {
        if (cfg.secrets.categories.apiKeys) {
            list.push(...API_KEY_PATTERNS.map((p) => ({
                ...p,
                severity: p.severity ?? "high",
                category: "secrets",
            })));
        }
        if (cfg.secrets.categories.cloudCredentials) {
            list.push(...CLOUD_CREDENTIAL_PATTERNS.map((p) => ({
                ...p,
                severity: p.severity ?? "high",
                category: "secrets",
            })));
        }
        if (cfg.secrets.categories.tokens) {
            list.push(...TOKEN_PATTERNS.map((p) => ({
                ...p,
                severity: p.severity ?? "high",
                category: "secrets",
            })));
        }
        if (cfg.secrets.categories.privateKeys) {
            list.push({
                type: "pem_private_key",
                regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/g,
                severity: "critical",
                category: "secrets",
            });
        }
    }
    // PII patterns
    if (cfg.pii.enabled) {
        const piiPatterns = getPiiPatterns({
            ssn: cfg.pii.categories.ssn,
            creditCard: cfg.pii.categories.creditCard,
            phone: cfg.pii.categories.phone,
            email: cfg.pii.categories.email,
        });
        list.push(...piiPatterns.map((p) => ({
            ...p,
            category: "pii",
        })));
    }
    // Custom patterns
    for (const { name, pattern, severity } of cfg.customPatterns) {
        try {
            const regex = new RegExp(pattern, "gi");
            list.push({
                type: `custom_${name}`,
                regex,
                severity: severity ?? "high",
                category: "custom",
            });
        }
        catch {
            // Skip invalid custom patterns
        }
    }
    return list;
}
/**
 * Find first secret match in text. Returns undefined if none.
 * Validates matches using the pattern's validator if present.
 */
export function detectFirst(text, patterns) {
    for (const { type, regex, validator, severity, category } of patterns) {
        regex.lastIndex = 0;
        let m;
        while ((m = regex.exec(text)) !== null) {
            const matchText = m[0];
            // If validator exists, only return if it passes
            if (validator) {
                if (validator(matchText)) {
                    return { type, index: m.index, length: matchText.length, severity, category };
                }
                // Continue searching for next match in this pattern
            }
            else {
                return { type, index: m.index, length: matchText.length, severity, category };
            }
        }
    }
    return undefined;
}
/**
 * Find all secret matches in text.
 * Validates matches using the pattern's validator if present.
 */
export function detectAll(text, patterns) {
    const matches = [];
    for (const { type, regex, validator, severity, category } of patterns) {
        regex.lastIndex = 0;
        let m;
        while ((m = regex.exec(text)) !== null) {
            const matchText = m[0];
            // If validator exists, only include if it passes
            if (validator) {
                if (validator(matchText)) {
                    matches.push({ type, index: m.index, length: matchText.length, severity, category });
                }
            }
            else {
                matches.push({ type, index: m.index, length: matchText.length, severity, category });
            }
        }
    }
    return matches;
}
//# sourceMappingURL=index.js.map