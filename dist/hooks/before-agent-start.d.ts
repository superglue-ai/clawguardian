/**
 * before_agent_start hook: inject ClawGuard instructions into the system prompt.
 */
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { ClawGuardConfig } from "../config.js";
export declare function registerBeforeAgentStartHook(api: OpenClawPluginApi, cfg: ClawGuardConfig): void;
//# sourceMappingURL=before-agent-start.d.ts.map