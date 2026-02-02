/**
 * before_tool_call hook: filter or block tool inputs containing secrets or destructive commands.
 */
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { ClawGuardConfig } from "../config.js";
export declare function registerBeforeToolCallHook(api: OpenClawPluginApi, cfg: ClawGuardConfig): void;
//# sourceMappingURL=before-tool-call.d.ts.map