/**
 * API key patterns (aligned with OpenClaw src/logging/redact.ts).
 */
import type { Severity } from "../config.js";
export type PatternSpec = {
    type: string;
    regex: RegExp;
    severity?: Severity;
};
export declare const API_KEY_PATTERNS: PatternSpec[];
//# sourceMappingURL=api-keys.d.ts.map