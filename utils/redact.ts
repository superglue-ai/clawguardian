/**
 * Redaction helpers: mask tokens, handle PEM blocks.
 */

import type { ClawGuardConfig } from "../config.js";
import { buildPatterns } from "../patterns/index.js";

const REDACT_MIN_LENGTH = 18;
const REDACT_KEEP_START = 6;
const REDACT_KEEP_END = 4;

function maskToken(token: string): string {
  if (token.length < REDACT_MIN_LENGTH) {
    return "***";
  }
  const start = token.slice(0, REDACT_KEEP_START);
  const end = token.slice(-REDACT_KEEP_END);
  return `${start}…${end}`;
}

function redactPemBlock(block: string): string {
  const lines = block.split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) {
    return "***";
  }
  return `${lines[0]}\n…redacted…\n${lines[lines.length - 1]}`;
}

function redactMatch(match: string, groups: string[]): string {
  if (match.includes("PRIVATE KEY-----")) {
    return redactPemBlock(match);
  }
  const token =
    groups
      .filter((value): value is string => typeof value === "string" && value.length > 0)
      .at(-1) ?? match;
  const masked = maskToken(token);
  if (token === match) {
    return masked;
  }
  return match.replace(token, masked);
}

/**
 * Redact sensitive data in text using config's pattern set.
 */
export function redactText(text: string, cfg: ClawGuardConfig): string {
  if (!text || typeof text !== "string") {
    return text;
  }
  const patterns = buildPatterns(cfg);

  let next = text;
  for (const { regex } of patterns) {
    next = next.replace(regex, (...args: string[]) =>
      redactMatch(args[0], args.slice(1, args.length - 2)),
    );
  }
  return next;
}

/**
 * Redact sensitive data in a JSON-serializable value (e.g. tool params).
 * Recursively processes strings; other values are passed through.
 */
export function redactParams(params: unknown, cfg: ClawGuardConfig): Record<string, unknown> {
  if (params === null || params === undefined) {
    return {};
  }
  if (typeof params !== "object" || Array.isArray(params)) {
    return typeof params === "object" && params !== null ? (params as Record<string, unknown>) : {};
  }

  const obj = params as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === "string") {
      out[key] = redactText(value, cfg);
    } else if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      out[key] = redactParams(value, cfg);
    } else if (Array.isArray(value)) {
      out[key] = value.map((item) => (typeof item === "string" ? redactText(item, cfg) : item));
    } else {
      out[key] = value;
    }
  }
  return out;
}
