/**
 * before_tool_call hook: filter or block tool inputs containing secrets or destructive commands.
 */
import { getActionForSeverity } from "../config.js";
import { detectDestructive } from "../destructive/index.js";
import { isAllowlisted } from "../utils/matcher.js";
import { detectSecret } from "../utils/matcher.js";
import { redactParams } from "../utils/redact.js";
/**
 * Check if the agent has explicitly confirmed this tool call.
 * The agent can add `_clawguardian_confirm: true` to acknowledge the risk.
 */
function hasConfirmFlag(params) {
    if (typeof params !== "object" || params === null) {
        return false;
    }
    const p = params;
    return p._clawguardian_confirm === true;
}
/**
 * Strip the confirm flag from params before passing to the tool.
 */
function stripConfirmFlag(params) {
    if (typeof params !== "object" || params === null) {
        return {};
    }
    const { _clawguardian_confirm, ...rest } = params;
    return rest;
}
function categoryEnabled(match, categories) {
    switch (match.category) {
        case "file_delete":
            return categories.fileDelete;
        case "git_destructive":
            return categories.gitDestructive;
        case "sql_destructive":
            return categories.sqlDestructive;
        case "system_destructive":
            return categories.systemDestructive;
        case "process_kill":
            return categories.processKill;
        case "network_destructive":
            return categories.networkDestructive;
        case "privilege_escalation":
            return categories.privilegeEscalation;
        default:
            return true;
    }
}
export function registerBeforeToolCallHook(api, cfg) {
    if (!cfg.filterToolInputs && !cfg.destructive.enabled) {
        return;
    }
    api.on("before_tool_call", async (event, ctx) => {
        const { toolName, params } = event;
        const sessionKey = ctx.sessionKey;
        if (isAllowlisted(cfg.allowlist, toolName, sessionKey)) {
            return;
        }
        // Check if agent has explicitly confirmed this call
        const confirmed = hasConfirmFlag(params);
        // Check for destructive commands first
        if (cfg.destructive.enabled) {
            const destructiveMatch = detectDestructive(toolName, params);
            if (destructiveMatch && categoryEnabled(destructiveMatch, cfg.destructive.categories)) {
                // Get action based on severity level
                const action = getActionForSeverity(destructiveMatch.severity, cfg.destructive);
                // Skip if action is "log" - just log silently
                if (action !== "log") {
                    const msg = `ClawGuardian: ${destructiveMatch.severity} severity - ${destructiveMatch.reason}`;
                    if (cfg.logging.logDetections) {
                        api.logger.warn(msg);
                    }
                }
                if (action === "block") {
                    return {
                        block: true,
                        blockReason: `Blocked by ClawGuardian: ${destructiveMatch.reason}`,
                    };
                }
                if (action === "confirm") {
                    // For exec tool, set ask: "always" to trigger OpenClaw's built-in approval flow
                    if (toolName === "exec" || toolName === "bash") {
                        return {
                            params: {
                                ...params,
                                ask: "always",
                                _clawguardian: {
                                    reason: destructiveMatch.reason,
                                    severity: destructiveMatch.severity,
                                    category: destructiveMatch.category,
                                },
                            },
                        };
                    }
                    // For non-exec tools, fall back to agent-confirm behavior
                }
                // agent-confirm: block until agent retries with _clawguardian_confirm: true
                if (action === "confirm" || action === "agent-confirm") {
                    if (confirmed) {
                        if (cfg.logging.logDetections) {
                            api.logger.info(`ClawGuardian: Agent confirmed destructive action - ${destructiveMatch.reason}`);
                        }
                        // Strip the confirm flag and allow
                        return { params: stripConfirmFlag(params) };
                    }
                    // Block and ask agent to confirm
                    return {
                        block: true,
                        blockReason: `ClawGuardian: ${destructiveMatch.reason}. To proceed, re-run with \`_clawguardian_confirm: true\` in params.`,
                    };
                }
                // action === "warn" or "log": continue (log was already done for "warn")
            }
        }
        // Check for secrets/PII
        if (cfg.filterToolInputs) {
            const paramsStr = JSON.stringify(params);
            const result = detectSecret(paramsStr, cfg);
            if (result) {
                const { match, action } = result;
                if (cfg.logging.logDetections && action !== "log") {
                    const msg = `ClawGuardian: ${match.type} (${match.severity}) detected in tool ${toolName} params`;
                    api.logger.warn(msg);
                }
                if (action === "block") {
                    return {
                        block: true,
                        blockReason: `Blocked by ClawGuardian: ${match.type} detected in tool parameters`,
                    };
                }
                if (action === "redact") {
                    const redacted = redactParams(params, cfg);
                    return { params: redacted };
                }
                // "confirm" for secrets on non-exec tools falls through to agent-confirm
                // "agent-confirm" for secrets: agent must explicitly acknowledge
                if (action === "confirm" || action === "agent-confirm") {
                    if (confirmed) {
                        if (cfg.logging.logDetections) {
                            api.logger.info(`ClawGuardian: Agent confirmed sending ${match.type} - proceeding with redaction`);
                        }
                        // Even with confirmation, redact the sensitive data
                        const redacted = redactParams(params, cfg);
                        return { params: { ...redacted, _clawguardian_confirmed: match.type } };
                    }
                    // Block and ask agent to confirm
                    return {
                        block: true,
                        blockReason: `ClawGuardian: ${match.type} detected. To proceed (with redaction), re-run with \`_clawguardian_confirm: true\` in params.`,
                    };
                }
            }
        }
        // Continue with original params (strip confirm flag if present)
        if (confirmed) {
            return { params: stripConfirmFlag(params) };
        }
        return;
    }, { priority: 100 });
}
//# sourceMappingURL=before-tool-call.js.map