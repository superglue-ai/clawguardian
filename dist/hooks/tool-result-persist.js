/**
 * tool_result_persist hook: redact or block secrets from tool results before persistence.
 * This hook is synchronous; do not return a Promise.
 */
import { detectSecret } from "../utils/matcher.js";
import { redactText } from "../utils/redact.js";
function isTextBlock(block) {
    return (typeof block === "object" &&
        block !== null &&
        block.type === "text" &&
        typeof block.text === "string");
}
export function registerToolResultPersistHook(api, cfg) {
    if (!cfg.filterToolOutputs) {
        return;
    }
    api.on("tool_result_persist", (event, _ctx) => {
        const msg = event.message;
        if (!msg.content || !Array.isArray(msg.content)) {
            return;
        }
        // First pass: check if any block contains a secret that should be blocked
        for (const block of msg.content) {
            if (isTextBlock(block)) {
                const result = detectSecret(block.text, cfg);
                if (result && result.action === "block") {
                    // Log the detection
                    if (cfg.logging.logDetections) {
                        api.logger.warn(`ClawGuard: Blocking tool output - ${result.match.type} (${result.match.severity}) detected`);
                    }
                    // Replace entire content with blocked message
                    msg.content = [
                        {
                            type: "text",
                            text: `[ClawGuard: Output blocked - ${result.match.type} detected]`,
                        },
                    ];
                    return { message: event.message };
                }
            }
        }
        // Second pass: redact secrets that should be redacted
        let modified = false;
        for (const block of msg.content) {
            if (isTextBlock(block)) {
                const redacted = redactText(block.text, cfg);
                if (redacted !== block.text) {
                    block.text = redacted;
                    modified = true;
                }
            }
        }
        if (modified) {
            return { message: event.message };
        }
        return;
    }, { priority: 100 });
}
//# sourceMappingURL=tool-result-persist.js.map