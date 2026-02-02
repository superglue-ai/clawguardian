/**
 * PII patterns: SSN, credit card, phone, email.
 * Uses validators for robust detection after regex matching.
 */
import type { Severity } from "../config.js";
import type { PatternSpec } from "./api-keys.js";
/**
 * Extended pattern spec with optional validator function and severity.
 * When a validator is present, regex matches are validated before being reported.
 */
export interface ValidatedPatternSpec extends PatternSpec {
    validator?: (match: string) => boolean;
    severity: Severity;
}
export declare const PII_SSN: ValidatedPatternSpec;
export declare const PII_SSN_NO_DASHES: ValidatedPatternSpec;
export declare const PII_CREDIT_CARD: ValidatedPatternSpec;
export declare const PII_PHONE: ValidatedPatternSpec;
export declare const PII_EMAIL: ValidatedPatternSpec;
export declare function getPiiPatterns(options: {
    ssn: boolean;
    creditCard: boolean;
    phone: boolean;
    email: boolean;
}): ValidatedPatternSpec[];
//# sourceMappingURL=pii.d.ts.map