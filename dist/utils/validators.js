/**
 * Validation utilities for PII detection.
 * Uses external libraries for robust validation after regex matching.
 */
import { isValidPhoneNumber, parsePhoneNumber } from "libphonenumber-js";
/**
 * Validate a credit card number using the Luhn algorithm.
 * This catches false positives from regex (random 16-digit numbers).
 * Also rejects obviously fake numbers like all zeros or all same digit.
 */
export function isValidCreditCard(candidate) {
    // Strip spaces and dashes
    const digits = candidate.replace(/[\s-]/g, "");
    // Must be 13-19 digits (standard card lengths)
    if (!/^\d{13,19}$/.test(digits)) {
        return false;
    }
    // Reject obviously fake patterns (all same digit)
    if (/^(\d)\1+$/.test(digits)) {
        return false;
    }
    // Luhn algorithm inline (avoid import issues)
    let sum = 0;
    let isEven = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let digit = parseInt(digits[i], 10);
        if (isEven) {
            digit *= 2;
            if (digit > 9) {
                digit -= 9;
            }
        }
        sum += digit;
        isEven = !isEven;
    }
    return sum % 10 === 0;
}
/**
 * Validate a phone number using libphonenumber-js.
 * Uses strict validation to ensure the number is actually valid.
 */
export function isValidPhone(candidate, defaultCountry = "US") {
    try {
        // First try parsing with the default country
        if (isValidPhoneNumber(candidate, defaultCountry)) {
            return true;
        }
        // Try parsing as international format
        const parsed = parsePhoneNumber(candidate);
        return parsed?.isValid() ?? false;
    }
    catch {
        return false;
    }
}
/**
 * Validate an SSN format (basic structure check).
 * SSNs have specific rules: area (001-899, not 666), group (01-99), serial (0001-9999).
 */
export function isValidSSN(candidate) {
    const match = candidate.match(/^(\d{3})-(\d{2})-(\d{4})$/);
    if (!match) {
        return false;
    }
    const [, area, group, serial] = match;
    const areaNum = parseInt(area, 10);
    const groupNum = parseInt(group, 10);
    const serialNum = parseInt(serial, 10);
    // Area cannot be 000, 666, or 900-999
    if (areaNum === 0 || areaNum === 666 || areaNum >= 900) {
        return false;
    }
    // Group cannot be 00
    if (groupNum === 0) {
        return false;
    }
    // Serial cannot be 0000
    if (serialNum === 0) {
        return false;
    }
    return true;
}
/**
 * Validate an email address (basic RFC-compliant check).
 * More permissive than strict RFC 5322 but catches obvious non-emails.
 */
export function isValidEmail(candidate) {
    // Basic structure: local@domain.tld
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    if (!emailRegex.test(candidate)) {
        return false;
    }
    // Additional checks
    const [local, domain] = candidate.split("@");
    // Local part shouldn't start/end with dots or have consecutive dots
    if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) {
        return false;
    }
    // Domain shouldn't start/end with dots or hyphens
    if (domain.startsWith(".") ||
        domain.startsWith("-") ||
        domain.endsWith(".") ||
        domain.endsWith("-")) {
        return false;
    }
    return true;
}
//# sourceMappingURL=validators.js.map