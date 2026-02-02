/**
 * ClawGuard — OpenClaw secret detection and PII filtering for tool calls.
 */
import { parseClawGuardConfig } from "./config.js";
import { registerBeforeAgentStartHook } from "./hooks/before-agent-start.js";
import { registerBeforeToolCallHook } from "./hooks/before-tool-call.js";
import { registerToolResultPersistHook } from "./hooks/tool-result-persist.js";
export default {
    id: "clawguard",
    name: "ClawGuard",
    description: "Secret detection, PII filtering, and destructive command protection",
    register(api) {
        const cfg = parseClawGuardConfig(api.pluginConfig);
        api.logger.info("ClawGuard: security filtering enabled");
        registerBeforeAgentStartHook(api, cfg);
        registerBeforeToolCallHook(api, cfg);
        registerToolResultPersistHook(api, cfg);
    },
};
//# sourceMappingURL=index.js.map