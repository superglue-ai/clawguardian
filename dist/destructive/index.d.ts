/**
 * Destructive tool call detection module.
 * Based on SafeExec patterns (https://github.com/agentify-sh/safeexec).
 */
export type { DestructiveCategory, DestructiveSeverity, DestructiveMatch } from "./detector.js";
export { detectDestructive, mightBeDestructive, isDestructiveRm, isDestructiveGit, isDestructiveSql, isDestructiveSystem, isDestructiveFind, isDestructiveXargs, isRemoteCodeExecution, isFileTruncation, hasDangerousPath, checkPrivilegeEscalation, } from "./detector.js";
//# sourceMappingURL=index.d.ts.map