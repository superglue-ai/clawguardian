/**
 * Pattern matching engine with allowlist support.
 */

import type { ClawGuardianAllowlist, ClawGuardianConfig, SeverityAction, Severity } from "../config.js";
import { getActionForSeverity } from "../config.js";
import { buildPatterns, detectAll, type SecretMatch } from "../patterns/index.js";

export type MatchResult = {
  match: SecretMatch;
  action: SeverityAction;
};

/**
 * Severity ranking for comparison (higher = more severe).
 */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Check if tool/session is allowlisted.
 */
export function isAllowlisted(
  allowlist: ClawGuardianAllowlist,
  toolName: string,
  sessionKey?: string,
): boolean {
  if (allowlist.tools?.includes(toolName)) {
    return true;
  }
  if (sessionKey && allowlist.sessions?.includes(sessionKey)) {
    return true;
  }
  return false;
}

/**
 * Check if a matched secret is allowlisted by pattern (e.g. test keys).
 */
export function isMatchAllowlisted(matchedText: string, allowlistPatterns: string[] = []): boolean {
  if (allowlistPatterns.length === 0) {
    return false;
  }
  for (const p of allowlistPatterns) {
    try {
      const re = new RegExp(p, "i");
      if (re.test(matchedText)) {
        return true;
      }
    } catch {
      // Skip invalid allowlist pattern
    }
  }
  return false;
}

/**
 * Get the appropriate config section for a match category.
 */
function getConfigForCategory(
  cfg: ClawGuardianConfig,
  category: SecretMatch["category"],
): { action: SeverityAction; severityActions: Record<Severity, SeverityAction> } {
  switch (category) {
    case "secrets":
      return cfg.secrets;
    case "pii":
      return cfg.pii;
    case "custom":
      // Custom patterns use secrets config as fallback
      return cfg.secrets;
  }
}

/**
 * Detect secrets in text; returns the highest severity match.
 * Respects allowlist patterns.
 */
export function detectSecret(text: string, cfg: ClawGuardianConfig): MatchResult | undefined {
  const patterns = buildPatterns(cfg);
  const allMatches = detectAll(text, patterns);

  if (allMatches.length === 0) {
    return undefined;
  }

  // Filter out allowlisted matches and find highest severity
  let highestMatch: SecretMatch | undefined;
  let highestRank = -1;

  for (const match of allMatches) {
    const matchedText = text.slice(match.index, match.index + match.length);
    if (isMatchAllowlisted(matchedText, cfg.allowlist.patterns)) {
      continue;
    }

    const rank = SEVERITY_RANK[match.severity];
    if (rank > highestRank) {
      highestRank = rank;
      highestMatch = match;
    }
  }

  if (!highestMatch) {
    return undefined;
  }

  // Check if custom pattern has explicit action override
  const customPattern = cfg.customPatterns.find((c) => `custom_${c.name}` === highestMatch.type);
  if (customPattern?.action) {
    return { match: highestMatch, action: customPattern.action };
  }

  // Get action based on severity and category
  const configSection = getConfigForCategory(cfg, highestMatch.category);
  const action = getActionForSeverity(highestMatch.severity, configSection);

  return { match: highestMatch, action };
}

/**
 * Check if text contains any secret (for block decision).
 */
export function hasSecret(text: string, cfg: ClawGuardianConfig): boolean {
  return detectSecret(text, cfg) !== undefined;
}

/**
 * Get action for highest severity detected secret.
 */
export function getActionForFirstMatch(
  text: string,
  cfg: ClawGuardianConfig,
): SeverityAction | undefined {
  const result = detectSecret(text, cfg);
  return result?.action;
}
