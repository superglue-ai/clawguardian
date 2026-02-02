/**
 * ClawGuardian — OpenClaw secret detection and PII filtering for tool calls.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { parseClawGuardianConfig } from "./config.js";
import { registerBeforeAgentStartHook } from "./hooks/before-agent-start.js";
import { registerBeforeToolCallHook } from "./hooks/before-tool-call.js";
import { registerToolResultPersistHook } from "./hooks/tool-result-persist.js";

export default {
  id: "clawguardian",
  name: "ClawGuardian",
  description: "Secret detection, PII filtering, and destructive command protection",

  register(api: OpenClawPluginApi): void {
    const cfg = parseClawGuardianConfig(api.pluginConfig);
    api.logger.info("ClawGuardian: security filtering enabled");

    registerBeforeAgentStartHook(api, cfg);
    registerBeforeToolCallHook(api, cfg);
    registerToolResultPersistHook(api, cfg);
  },
};
