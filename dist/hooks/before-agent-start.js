/**
 * before_agent_start hook: inject ClawGuardian instructions into the system prompt.
 */
/**
 * Build the ClawGuardian context to inject into the system prompt.
 */
function buildClawGuardianContext(_cfg) {
    return `<clawguardian>
ClawGuardian active. If a tool call is blocked, add "_clawguardian_confirm": true to params and retry.
</clawguardian>`;
}
export function registerBeforeAgentStartHook(api, _cfg) {
    api.on("before_agent_start", (_event, _ctx) => {
        const context = buildClawGuardianContext(_cfg);
        return {
            prependContext: context,
        };
    }, { priority: 50 });
}
//# sourceMappingURL=before-agent-start.js.map