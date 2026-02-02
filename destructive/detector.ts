/**
 * Destructive tool call detection - based on SafeExec patterns.
 * https://github.com/agentify-sh/safeexec
 *
 * SafeExec is battle-tested for AI agents (Codex/GPT) and provides
 * well-defined patterns for dangerous commands.
 */

export type DestructiveCategory =
  | "file_delete"
  | "git_destructive"
  | "sql_destructive"
  | "system_destructive"
  | "process_kill"
  | "network_destructive"
  | "privilege_escalation";

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
export function isDestructiveRm(args: string[]): DestructiveMatch | undefined {
  let force = false;
  let recursive = false;

  for (const arg of args) {
    if (arg === "--") {
      break;
    }
    if (arg === "--force") {
      force = true;
    }
    if (arg === "--recursive") {
      recursive = true;
    }
    if (arg.startsWith("-") && arg !== "-" && arg !== "--") {
      // Check for force and recursive flags in combined options like -rf
      const hasForceFlag = arg.includes("f");
      const hasRecursiveFlag = arg.includes("r") || arg.includes("R");
      if (hasForceFlag) {
        force = true;
      }
      if (hasRecursiveFlag) {
        recursive = true;
      }
    }
  }

  if (force && recursive) {
    return {
      category: "file_delete",
      reason: "Recursive force deletion (rm -rf)",
      severity: "critical",
      pattern: "rm -rf",
    };
  }
  return undefined;
}

/**
 * Check if git command is destructive (SafeExec patterns).
 * Always gated: reset, revert, checkout, restore
 * Gated if forced: clean -f, switch -f/--discard-changes
 * Gated stash ops: drop, clear, pop
 */
export function isDestructiveGit(args: string[]): DestructiveMatch | undefined {
  // Parse global git flags to find subcommand
  let subcmd = "";
  let subcmdIdx = -1;
  let i = 0;

  while (i < args.length) {
    const a = args[i];
    // Skip global options with values
    if (a.match(/^--.*=.*/)) {
      i++;
      continue;
    }
    if (
      [
        "-C",
        "-c",
        "--exec-path",
        "--html-path",
        "--man-path",
        "--info-path",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
      ].includes(a)
    ) {
      i += 2;
      continue;
    }
    if (a === "--") {
      i++;
      break;
    }
    if (a.startsWith("-")) {
      i++;
      continue;
    }
    // Found subcommand
    subcmd = a;
    subcmdIdx = i;
    break;
  }

  if (!subcmd) {
    return undefined;
  }

  // Always gated subcommands
  if (["reset", "revert", "checkout", "restore"].includes(subcmd)) {
    // Check for --hard flag (especially dangerous for reset)
    const hasHard = args.some((a) => a === "--hard");
    return {
      category: "git_destructive",
      reason: `git ${subcmd}${hasHard ? " --hard" : ""} can lose uncommitted changes`,
      severity: hasHard ? "critical" : "high",
      pattern: `git ${subcmd}`,
    };
  }

  // git clean - gated if forced
  if (subcmd === "clean") {
    const hasForce = args.some((a) => a === "-f" || a === "--force");
    if (hasForce) {
      return {
        category: "git_destructive",
        reason: "git clean -f removes untracked files permanently",
        severity: "high",
        pattern: "git clean -f",
      };
    }
  }

  // git switch - gated if forced or discard-changes
  if (subcmd === "switch") {
    const hasForce = args.some((a) => a === "-f" || a === "--force" || a === "--discard-changes");
    if (hasForce) {
      return {
        category: "git_destructive",
        reason: "git switch with force/discard-changes loses uncommitted work",
        severity: "high",
        pattern: "git switch -f",
      };
    }
  }

  // git stash - gated for drop, clear, pop
  if (subcmd === "stash" && subcmdIdx + 1 < args.length) {
    const stashOp = args[subcmdIdx + 1];
    if (["drop", "clear", "pop"].includes(stashOp)) {
      return {
        category: "git_destructive",
        reason: `git stash ${stashOp} can lose stashed changes`,
        severity: stashOp === "clear" ? "critical" : "high",
        pattern: `git stash ${stashOp}`,
      };
    }
  }

  // git push --force
  if (subcmd === "push") {
    const hasForce = args.some((a) => a === "-f" || a === "--force" || a === "--force-with-lease");
    if (hasForce) {
      return {
        category: "git_destructive",
        reason: "git push --force can overwrite remote history",
        severity: "critical",
        pattern: "git push --force",
      };
    }
  }

  // git branch -d/-D
  if (subcmd === "branch") {
    const hasDelete = args.some((a) => a === "-d" || a === "-D" || a === "--delete");
    if (hasDelete) {
      return {
        category: "git_destructive",
        reason: "git branch delete removes branch",
        severity: "medium",
        pattern: "git branch -d",
      };
    }
  }

  // git reflog expire/delete
  if (subcmd === "reflog" && subcmdIdx + 1 < args.length) {
    const reflogOp = args[subcmdIdx + 1];
    if (["expire", "delete"].includes(reflogOp)) {
      return {
        category: "git_destructive",
        reason: `git reflog ${reflogOp} removes recovery points`,
        severity: "critical",
        pattern: `git reflog ${reflogOp}`,
      };
    }
  }

  return undefined;
}

/**
 * SQL destructive patterns.
 */
export function isDestructiveSql(text: string): DestructiveMatch | undefined {
  const patterns: Array<{
    pattern: RegExp;
    reason: string;
    severity: DestructiveSeverity;
    name: string;
  }> = [
    {
      pattern: /\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b/i,
      reason: "SQL DROP statement permanently removes data",
      severity: "critical",
      name: "DROP",
    },
    {
      pattern: /\bTRUNCATE\s+TABLE\b/i,
      reason: "SQL TRUNCATE removes all rows from table",
      severity: "critical",
      name: "TRUNCATE",
    },
    {
      pattern: /\bDELETE\s+FROM\s+\w+\s*(?:;|$)/i,
      reason: "DELETE without WHERE clause removes all rows",
      severity: "critical",
      name: "DELETE without WHERE",
    },
    {
      pattern: /\bUPDATE\s+\w+\s+SET\s+(?!.*\bWHERE\b)/i,
      reason: "UPDATE without WHERE clause modifies all rows",
      severity: "high",
      name: "UPDATE without WHERE",
    },
    {
      pattern: /\bALTER\s+TABLE\s+\w+\s+DROP\b/i,
      reason: "ALTER TABLE DROP removes column/constraint",
      severity: "high",
      name: "ALTER TABLE DROP",
    },
  ];

  for (const { pattern, reason, severity, name } of patterns) {
    if (pattern.test(text)) {
      return {
        category: "sql_destructive",
        reason,
        severity,
        pattern: name,
      };
    }
  }
  return undefined;
}

/**
 * System destructive commands.
 */
export function isDestructiveSystem(command: string, args: string[]): DestructiveMatch | undefined {
  const cmd = command.toLowerCase();

  // Shutdown/reboot commands
  if (["shutdown", "reboot", "halt", "poweroff", "init"].includes(cmd)) {
    return {
      category: "system_destructive",
      reason: `${cmd} will shut down or restart the system`,
      severity: "critical",
      pattern: cmd,
    };
  }

  // Disk formatting
  if (["format", "fdisk", "mkfs", "dd", "parted", "gdisk"].includes(cmd)) {
    return {
      category: "system_destructive",
      reason: `${cmd} can destroy disk data`,
      severity: "critical",
      pattern: cmd,
    };
  }

  // Process killing
  if (["kill", "pkill", "killall"].includes(cmd)) {
    const hasSignal9 = args.some((a) => a === "-9" || a === "-KILL" || a === "-SIGKILL");
    return {
      category: "process_kill",
      reason: `${cmd}${hasSignal9 ? " -9" : ""} terminates processes`,
      severity: hasSignal9 ? "high" : "medium",
      pattern: cmd,
    };
  }

  // Firewall modification
  if (["iptables", "firewall-cmd", "ufw", "nft"].includes(cmd)) {
    return {
      category: "network_destructive",
      reason: `${cmd} modifies firewall rules`,
      severity: "high",
      pattern: cmd,
    };
  }

  // chmod/chown on sensitive paths
  if (["chmod", "chown", "chgrp"].includes(cmd)) {
    const hasRecursive = args.some((a) => a === "-R" || a === "--recursive");
    const hasSensitivePath = args.some(
      (a) =>
        a === "/" ||
        a === "~" ||
        a.startsWith("/etc") ||
        a.startsWith("/usr") ||
        a.startsWith("/bin") ||
        a.startsWith("/sbin"),
    );
    if (hasRecursive && hasSensitivePath) {
      return {
        category: "system_destructive",
        reason: `${cmd} -R on system directory can break the system`,
        severity: "critical",
        pattern: `${cmd} -R`,
      };
    }
  }

  return undefined;
}

/**
 * Check for privilege escalation commands (sudo, doas, su, pkexec).
 * Returns the match and the remaining command/args after stripping the prefix.
 */
export function checkPrivilegeEscalation(
  command: string,
  args: string[],
): { match: DestructiveMatch; innerCommand: string; innerArgs: string[] } | undefined {
  const cmd = command.toLowerCase();

  // Privilege escalation commands
  const privEscCommands = ["sudo", "doas", "pkexec", "su"];

  if (!privEscCommands.includes(cmd)) {
    return undefined;
  }

  // Parse sudo/doas flags to find the actual command
  let innerCommand = "";
  let innerArgs: string[] = [];
  let i = 0;

  if (cmd === "sudo" || cmd === "doas") {
    // Skip sudo/doas flags to find the actual command
    while (i < args.length) {
      const a = args[i];
      // sudo flags that take a value
      if (["-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D"].includes(a)) {
        i += 2;
        continue;
      }
      // sudo flags without value
      if (a.startsWith("-")) {
        i++;
        continue;
      }
      // Found the actual command
      innerCommand = a;
      innerArgs = args.slice(i + 1);
      break;
    }
  } else if (cmd === "su") {
    // su - user -c "command" or su user
    const cIdx = args.indexOf("-c");
    if (cIdx !== -1 && cIdx + 1 < args.length) {
      // Command is in -c argument
      const cmdStr = args[cIdx + 1];
      const parts = cmdStr.split(/\s+/);
      innerCommand = parts[0] || "";
      innerArgs = parts.slice(1);
    }
  } else if (cmd === "pkexec") {
    // pkexec [options] command [args]
    while (i < args.length) {
      const a = args[i];
      if (a.startsWith("-")) {
        i++;
        continue;
      }
      innerCommand = a;
      innerArgs = args.slice(i + 1);
      break;
    }
  }

  return {
    match: {
      category: "privilege_escalation",
      reason: `${cmd} runs command with elevated privileges`,
      severity: "high",
      pattern: cmd,
    },
    innerCommand,
    innerArgs,
  };
}

/**
 * Check for dangerous paths in arguments.
 */
export function hasDangerousPath(args: string[]): DestructiveMatch | undefined {
  const dangerousPaths = [
    { pattern: /^\/$/, reason: "Root directory", severity: "critical" as const },
    { pattern: /^~$/, reason: "Home directory", severity: "critical" as const },
    { pattern: /^\$HOME$/i, reason: "Home directory", severity: "critical" as const },
    { pattern: /^\/etc\b/, reason: "System config directory", severity: "critical" as const },
    { pattern: /^\/usr\b/, reason: "System directory", severity: "critical" as const },
    { pattern: /^\/bin\b/, reason: "System binaries", severity: "critical" as const },
    { pattern: /^\/sbin\b/, reason: "System binaries", severity: "critical" as const },
    { pattern: /^\/boot\b/, reason: "Boot directory", severity: "critical" as const },
    { pattern: /^\/var\/log\b/, reason: "System logs", severity: "high" as const },
    { pattern: /^\/var\/lib\b/, reason: "System data", severity: "high" as const },
    { pattern: /^C:\\Windows/i, reason: "Windows system directory", severity: "critical" as const },
    { pattern: /^C:\\Program Files/i, reason: "Windows programs", severity: "critical" as const },
    { pattern: /System32/i, reason: "Windows system directory", severity: "critical" as const },
    { pattern: /\.ssh\b/, reason: "SSH configuration", severity: "high" as const },
    { pattern: /\.gnupg\b/, reason: "GPG configuration", severity: "high" as const },
    { pattern: /\*\s*$/, reason: "Wildcard pattern", severity: "medium" as const },
  ];

  for (const arg of args) {
    for (const { pattern, reason, severity } of dangerousPaths) {
      if (pattern.test(arg)) {
        return {
          category: "file_delete",
          reason: `Operation on ${reason}`,
          severity,
          pattern: arg,
        };
      }
    }
  }
  return undefined;
}

/**
 * Check for find command with -delete or -exec rm.
 */
export function isDestructiveFind(args: string[]): DestructiveMatch | undefined {
  const hasDelete = args.some((a) => a === "-delete");
  const hasExecRm = args.some((a, i) => {
    if (a === "-exec" && i + 1 < args.length) {
      const execCmd = args[i + 1];
      return execCmd === "rm" || execCmd.endsWith("/rm");
    }
    return false;
  });

  if (hasDelete || hasExecRm) {
    // Check for dangerous starting paths
    const startPath = args.find((a) => !a.startsWith("-") && a !== "find");
    const isDangerousPath =
      startPath === "/" ||
      startPath === "~" ||
      startPath === "$HOME" ||
      startPath?.startsWith("/etc") ||
      startPath?.startsWith("/usr");

    return {
      category: "file_delete",
      reason: `find with ${hasDelete ? "-delete" : "-exec rm"} can remove many files`,
      severity: isDangerousPath ? "critical" : "high",
      pattern: hasDelete ? "find -delete" : "find -exec rm",
    };
  }
  return undefined;
}

/**
 * Check for xargs with rm or other dangerous commands.
 */
export function isDestructiveXargs(args: string[]): DestructiveMatch | undefined {
  // Look for rm in xargs arguments
  const rmIdx = args.findIndex((a) => a === "rm" || a.endsWith("/rm"));
  if (rmIdx !== -1) {
    // Check if rm has -rf flags
    const rmArgs = args.slice(rmIdx + 1);
    const rmMatch = isDestructiveRm(rmArgs);
    if (rmMatch) {
      return {
        ...rmMatch,
        reason: `xargs ${rmMatch.reason}`,
        pattern: `xargs ${rmMatch.pattern}`,
      };
    }
    return {
      category: "file_delete",
      reason: "xargs rm can delete many files",
      severity: "high",
      pattern: "xargs rm",
    };
  }
  return undefined;
}

/**
 * Check for piped remote code execution (curl|bash, wget|sh, etc.).
 */
export function isRemoteCodeExecution(fullCommand: string): DestructiveMatch | undefined {
  // Patterns for piped remote code execution
  const patterns = [
    { pattern: /\b(?:curl|wget)\b[^|]*\|\s*(?:bash|sh|zsh|ksh|fish)\b/i, name: "curl|bash" },
    { pattern: /\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|ksh|fish)\b/i, name: "curl|sudo bash" },
    { pattern: /\bpython[23]?\s+-c\s+["'].*(?:urllib|requests).*exec/i, name: "python remote exec" },
    { pattern: /\beval\s+["'`]\$\((?:curl|wget)/i, name: "eval $(curl)" },
  ];

  for (const { pattern, name } of patterns) {
    if (pattern.test(fullCommand)) {
      return {
        category: "system_destructive",
        reason: `Remote code execution via ${name}`,
        severity: "critical",
        pattern: name,
      };
    }
  }
  return undefined;
}

/**
 * Check for file truncation (> /path).
 */
export function isFileTruncation(fullCommand: string): DestructiveMatch | undefined {
  // Match > /path or >| /path (clobber) at start or after semicolon/&&/||
  const truncatePattern = /(?:^|[;&|])\s*>[\s|]*([^\s;&|]+)/;
  const match = fullCommand.match(truncatePattern);

  if (match) {
    const path = match[1];
    // Check if it's a dangerous path
    const dangerousPaths = ["/etc/", "/usr/", "/bin/", "/sbin/", "/boot/", "/var/"];
    const isDangerous = dangerousPaths.some((p) => path.startsWith(p)) || path === "/dev/null";

    if (isDangerous || path.startsWith("/")) {
      return {
        category: "file_delete",
        reason: `File truncation can destroy ${path}`,
        severity: isDangerous ? "critical" : "high",
        pattern: `> ${path}`,
      };
    }
  }
  return undefined;
}

/**
 * Main detection function - checks all patterns.
 */
export function detectDestructive(
  toolName: string,
  params: Record<string, unknown>,
): DestructiveMatch | undefined {
  const name = toolName.toLowerCase();

  // Extract command and args from common parameter patterns
  let command = "";
  let args: string[] = [];
  let fullCommand = "";

  // Handle different tool parameter formats
  if (typeof params.command === "string") {
    fullCommand = params.command;
    const parts = params.command.split(/\s+/);
    command = parts[0] || "";
    args = parts.slice(1);
  } else if (typeof params.cmd === "string") {
    fullCommand = params.cmd;
    const parts = params.cmd.split(/\s+/);
    command = parts[0] || "";
    args = parts.slice(1);
  } else if (Array.isArray(params.args)) {
    args = params.args.map(String);
    command = args[0] || "";
    args = args.slice(1);
    fullCommand = params.args.join(" ");
  } else if (typeof params.input === "string") {
    fullCommand = params.input;
    // Check for SQL in input
    const sqlMatch = isDestructiveSql(params.input);
    if (sqlMatch) {
      return sqlMatch;
    }
  }

  // Check for remote code execution patterns in full command
  if (fullCommand) {
    const rceMatch = isRemoteCodeExecution(fullCommand);
    if (rceMatch) {
      return rceMatch;
    }

    const truncateMatch = isFileTruncation(fullCommand);
    if (truncateMatch) {
      return truncateMatch;
    }
  }

  // Normalize command name
  let cmdName = command.split("/").pop()?.toLowerCase() || name;

  // Check for privilege escalation (sudo, doas, su, pkexec)
  const privEsc = checkPrivilegeEscalation(cmdName, args);
  if (privEsc) {
    // Check if the inner command is also destructive (escalates severity)
    const innerCmdName = privEsc.innerCommand.split("/").pop()?.toLowerCase() || "";

    // Check inner command for destructive patterns
    if (innerCmdName === "rm" || innerCmdName === "del" || innerCmdName === "remove") {
      const rmMatch = isDestructiveRm(privEsc.innerArgs);
      if (rmMatch) {
        return {
          ...rmMatch,
          reason: `sudo ${rmMatch.reason}`,
          severity: "critical", // Escalate to critical when sudo + rm -rf
          pattern: `sudo ${rmMatch.pattern}`,
        };
      }
    }

    if (innerCmdName === "git") {
      const gitMatch = isDestructiveGit(privEsc.innerArgs);
      if (gitMatch) {
        return {
          ...gitMatch,
          reason: `sudo ${gitMatch.reason}`,
          pattern: `sudo ${gitMatch.pattern}`,
        };
      }
    }

    if (innerCmdName === "find") {
      const findMatch = isDestructiveFind(privEsc.innerArgs);
      if (findMatch) {
        return {
          ...findMatch,
          reason: `sudo ${findMatch.reason}`,
          severity: "critical",
          pattern: `sudo ${findMatch.pattern}`,
        };
      }
    }

    // Check inner command for system destructive
    const innerSysMatch = isDestructiveSystem(innerCmdName, privEsc.innerArgs);
    if (innerSysMatch) {
      return {
        ...innerSysMatch,
        reason: `sudo ${innerSysMatch.reason}`,
        severity: "critical", // Escalate when sudo + system command
        pattern: `sudo ${innerSysMatch.pattern}`,
      };
    }

    // Check inner command for dangerous paths
    const innerPathMatch = hasDangerousPath(privEsc.innerArgs);
    if (innerPathMatch) {
      return {
        ...innerPathMatch,
        reason: `sudo ${innerPathMatch.reason}`,
        severity: "critical",
        pattern: `sudo ${innerPathMatch.pattern}`,
      };
    }

    // Return the privilege escalation match itself
    return privEsc.match;
  }

  // Check specific command patterns
  if (cmdName === "rm" || cmdName === "del" || cmdName === "remove") {
    const rmMatch = isDestructiveRm(args);
    if (rmMatch) {
      return rmMatch;
    }
  }

  if (cmdName === "git") {
    const gitMatch = isDestructiveGit(args);
    if (gitMatch) {
      return gitMatch;
    }
  }

  if (cmdName === "find") {
    const findMatch = isDestructiveFind(args);
    if (findMatch) {
      return findMatch;
    }
  }

  if (cmdName === "xargs") {
    const xargsMatch = isDestructiveXargs(args);
    if (xargsMatch) {
      return xargsMatch;
    }
  }

  // Check system commands
  const sysMatch = isDestructiveSystem(cmdName, args);
  if (sysMatch) {
    return sysMatch;
  }

  // Check for dangerous paths
  const pathMatch = hasDangerousPath(args);
  if (pathMatch) {
    return pathMatch;
  }

  // Check for SQL in any string parameter
  for (const value of Object.values(params)) {
    if (typeof value === "string") {
      const sqlMatch = isDestructiveSql(value);
      if (sqlMatch) {
        return sqlMatch;
      }
    }
  }

  return undefined;
}

/**
 * Quick check if a tool call might be destructive.
 */
export function mightBeDestructive(toolName: string, params: Record<string, unknown>): boolean {
  return detectDestructive(toolName, params) !== undefined;
}
