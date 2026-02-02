/**
 * Pattern registry: aggregates patterns by category for ClawGuardian.
 */
import type { ClawGuardianConfig, Severity } from "../config.js";
export type { PatternSpec } from "./api-keys.js";
export type { ValidatedPatternSpec } from "./pii.js";
export { API_KEY_PATTERNS } from "./api-keys.js";
export { CLOUD_CREDENTIAL_PATTERNS } from "./cloud-credentials.js";
export { TOKEN_PATTERNS } from "./tokens.js";
export { getPiiPatterns, PII_SSN, PII_SSN_NO_DASHES, PII_CREDIT_CARD, PII_PHONE, PII_EMAIL } from "./pii.js";
export type SecretMatch = {
    type: string;
    index: number;
    length: number;
    severity: Severity;
    category: "secrets" | "pii" | "custom";
};
/**
 * Extended pattern with optional validator and severity.
 */
export type PatternWithValidator = {
    type: string;
    regex: RegExp;
    validator?: (match: string) => boolean;
    severity: Severity;
    category: "secrets" | "pii" | "custom";
};
/**
 * Build all active regex patterns from config.
 */
export declare function buildPatterns(cfg: ClawGuardianConfig): PatternWithValidator[];
/**
 * Find first secret match in text. Returns undefined if none.
 * Validates matches using the pattern's validator if present.
 */
export declare function detectFirst(text: string, patterns: PatternWithValidator[]): SecretMatch | undefined;
/**
 * Find all secret matches in text.
 * Validates matches using the pattern's validator if present.
 */
export declare function detectAll(text: string, patterns: PatternWithValidator[]): SecretMatch[];
//# sourceMappingURL=index.d.ts.map