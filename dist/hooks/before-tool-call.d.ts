/**
 * before_tool_call hook: filter or block tool inputs containing secrets or destructive commands.
 */
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { ClawGuardianConfig } from "../config.js";
export declare function registerBeforeToolCallHook(api: OpenClawPluginApi, cfg: ClawGuardianConfig): void;
//# sourceMappingURL=before-tool-call.d.ts.map