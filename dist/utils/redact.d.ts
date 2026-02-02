/**
 * Redaction helpers: mask tokens, handle PEM blocks.
 */
import type { ClawGuardianConfig } from "../config.js";
/**
 * Redact sensitive data in text using config's pattern set.
 */
export declare function redactText(text: string, cfg: ClawGuardianConfig): string;
/**
 * Redact sensitive data in a JSON-serializable value (e.g. tool params).
 * Recursively processes strings; other values are passed through.
 */
export declare function redactParams(params: unknown, cfg: ClawGuardianConfig): Record<string, unknown>;
//# sourceMappingURL=redact.d.ts.map