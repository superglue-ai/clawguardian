/**
 * Redaction helpers: mask tokens, handle PEM blocks.
 */
import type { ClawGuardConfig } from "../config.js";
/**
 * Redact sensitive data in text using config's pattern set.
 */
export declare function redactText(text: string, cfg: ClawGuardConfig): string;
/**
 * Redact sensitive data in a JSON-serializable value (e.g. tool params).
 * Recursively processes strings; other values are passed through.
 */
export declare function redactParams(params: unknown, cfg: ClawGuardConfig): Record<string, unknown>;
//# sourceMappingURL=redact.d.ts.map