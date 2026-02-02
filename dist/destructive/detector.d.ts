/**
 * Destructive tool call detection - based on SafeExec patterns.
 * https://github.com/agentify-sh/safeexec
 *
 * SafeExec is battle-tested for AI agents (Codex/GPT) and provides
 * well-defined patterns for dangerous commands.
 */
export type DestructiveCategory = "file_delete" | "git_destructive" | "sql_destructive" | "system_destructive" | "process_kill" | "network_destructive" | "privilege_escalation";
export type DestructiveSeverity = "low" | "medium" | "high" | "critical";
export type DestructiveMatch = {
    category: DestructiveCategory;
    reason: string;
    severity: DestructiveSeverity;
    pattern: string;
};
/**
 * Check if rm command has both recursive and force flags (SafeExec pattern).
 * Gates: rm -rf, rm -fr, rm --recursive --force
 */
export declare function isDestructiveRm(args: string[]): DestructiveMatch | undefined;
/**
 * Check if git command is destructive (SafeExec patterns).
 * Always gated: reset, revert, checkout, restore
 * Gated if forced: clean -f, switch -f/--discard-changes
 * Gated stash ops: drop, clear, pop
 */
export declare function isDestructiveGit(args: string[]): DestructiveMatch | undefined;
/**
 * SQL destructive patterns.
 */
export declare function isDestructiveSql(text: string): DestructiveMatch | undefined;
/**
 * System destructive commands.
 */
export declare function isDestructiveSystem(command: string, args: string[]): DestructiveMatch | undefined;
/**
 * Check for privilege escalation commands (sudo, doas, su, pkexec).
 * Returns the match and the remaining command/args after stripping the prefix.
 */
export declare function checkPrivilegeEscalation(command: string, args: string[]): {
    match: DestructiveMatch;
    innerCommand: string;
    innerArgs: string[];
} | undefined;
/**
 * Check for dangerous paths in arguments.
 */
export declare function hasDangerousPath(args: string[]): DestructiveMatch | undefined;
/**
 * Check for find command with -delete or -exec rm.
 */
export declare function isDestructiveFind(args: string[]): DestructiveMatch | undefined;
/**
 * Check for xargs with rm or other dangerous commands.
 */
export declare function isDestructiveXargs(args: string[]): DestructiveMatch | undefined;
/**
 * Check for piped remote code execution (curl|bash, wget|sh, etc.).
 */
export declare function isRemoteCodeExecution(fullCommand: string): DestructiveMatch | undefined;
/**
 * Check for file truncation (> /path).
 */
export declare function isFileTruncation(fullCommand: string): DestructiveMatch | undefined;
/**
 * Main detection function - checks all patterns.
 */
export declare function detectDestructive(toolName: string, params: Record<string, unknown>): DestructiveMatch | undefined;
/**
 * Quick check if a tool call might be destructive.
 */
export declare function mightBeDestructive(toolName: string, params: Record<string, unknown>): boolean;
//# sourceMappingURL=detector.d.ts.map