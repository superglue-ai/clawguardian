/**
 * Pattern matching engine with allowlist support.
 */
import type { ClawGuardianAllowlist, ClawGuardianConfig, SeverityAction } from "../config.js";
import { type SecretMatch } from "../patterns/index.js";
export type MatchResult = {
    match: SecretMatch;
    action: SeverityAction;
};
/**
 * Check if tool/session is allowlisted.
 */
export declare function isAllowlisted(allowlist: ClawGuardianAllowlist, toolName: string, sessionKey?: string): boolean;
/**
 * Check if a matched secret is allowlisted by pattern (e.g. test keys).
 */
export declare function isMatchAllowlisted(matchedText: string, allowlistPatterns?: string[]): boolean;
/**
 * Detect secrets in text; returns the highest severity match.
 * Respects allowlist patterns.
 */
export declare function detectSecret(text: string, cfg: ClawGuardianConfig): MatchResult | undefined;
/**
 * Check if text contains any secret (for block decision).
 */
export declare function hasSecret(text: string, cfg: ClawGuardianConfig): boolean;
/**
 * Get action for highest severity detected secret.
 */
export declare function getActionForFirstMatch(text: string, cfg: ClawGuardianConfig): SeverityAction | undefined;
//# sourceMappingURL=matcher.d.ts.map