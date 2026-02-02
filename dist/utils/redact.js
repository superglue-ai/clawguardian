/**
 * Redaction helpers: mask tokens, handle PEM blocks.
 */
import { buildPatterns } from "../patterns/index.js";
const REDACT_PLACEHOLDER = "[REDACTED]";
function maskToken(_token) {
    return REDACT_PLACEHOLDER;
}
function redactPemBlock(block) {
    const lines = block.split(/\r?\n/).filter(Boolean);
    if (lines.length < 2) {
        return "***";
    }
    return `${lines[0]}\n…redacted…\n${lines[lines.length - 1]}`;
}
function redactMatch(match, groups) {
    if (match.includes("PRIVATE KEY-----")) {
        return redactPemBlock(match);
    }
    const token = groups
        .filter((value) => typeof value === "string" && value.length > 0)
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
export function redactText(text, cfg) {
    if (!text || typeof text !== "string") {
        return text;
    }
    const patterns = buildPatterns(cfg);
    let next = text;
    for (const { regex } of patterns) {
        next = next.replace(regex, (...args) => redactMatch(args[0], args.slice(1, args.length - 2)));
    }
    return next;
}
/**
 * Redact sensitive data in a JSON-serializable value (e.g. tool params).
 * Recursively processes strings; other values are passed through.
 */
export function redactParams(params, cfg) {
    if (params === null || params === undefined) {
        return {};
    }
    if (typeof params !== "object" || Array.isArray(params)) {
        return typeof params === "object" && params !== null ? params : {};
    }
    const obj = params;
    const out = {};
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === "string") {
            out[key] = redactText(value, cfg);
        }
        else if (value !== null && typeof value === "object" && !Array.isArray(value)) {
            out[key] = redactParams(value, cfg);
        }
        else if (Array.isArray(value)) {
            out[key] = value.map((item) => (typeof item === "string" ? redactText(item, cfg) : item));
        }
        else {
            out[key] = value;
        }
    }
    return out;
}
//# sourceMappingURL=redact.js.map