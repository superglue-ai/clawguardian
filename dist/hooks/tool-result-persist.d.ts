/**
 * tool_result_persist hook: redact or block secrets from tool results before persistence.
 * This hook is synchronous; do not return a Promise.
 */
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { ClawGuardianConfig } from "../config.js";
export declare function registerToolResultPersistHook(api: OpenClawPluginApi, cfg: ClawGuardianConfig): void;
//# sourceMappingURL=tool-result-persist.d.ts.map