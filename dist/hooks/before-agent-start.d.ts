/**
 * before_agent_start hook: inject ClawGuardian instructions into the system prompt.
 */
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { ClawGuardianConfig } from "../config.js";
export declare function registerBeforeAgentStartHook(api: OpenClawPluginApi, _cfg: ClawGuardianConfig): void;
//# sourceMappingURL=before-agent-start.d.ts.map