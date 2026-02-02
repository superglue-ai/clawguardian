/**
 * PII patterns: SSN, credit card, phone, email.
 * Uses validators for robust detection after regex matching.
 */
import { isValidCreditCard, isValidEmail, isValidPhone, isValidSSN } from "../utils/validators.js";
export const PII_SSN = {
    type: "pii_ssn",
    // Match SSN with dashes: 123-45-6789
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    validator: isValidSSN,
    severity: "high",
};
export const PII_SSN_NO_DASHES = {
    type: "pii_ssn_no_dashes",
    // Match SSN without dashes: 123456789 (9 consecutive digits)
    // Only match when in SSN-like context to reduce false positives
    regex: /(?:ssn|social\s*security)[^\d]*(\d{9})\b/gi,
    validator: (match) => {
        // Extract just the digits
        const digits = match.replace(/\D/g, "");
        if (digits.length !== 9) {
            return false;
        }
        // Format as SSN and validate
        const formatted = `${digits.slice(0, 3)}-${digits.slice(3, 5)}-${digits.slice(5)}`;
        return isValidSSN(formatted);
    },
    severity: "high",
};
export const PII_CREDIT_CARD = {
    type: "pii_credit_card",
    // Match 13-19 digit cards with optional separators (covers Visa, MC, Amex, Discover, etc.)
    // Amex: 15 digits, Visa/MC/Discover: 16 digits, some cards: 13-19 digits
    regex: /\b(?:\d{4}[- ]?){2,4}\d{1,4}\b/g,
    validator: isValidCreditCard,
    severity: "high",
};
export const PII_PHONE = {
    type: "pii_phone",
    // Match common formats: (212) 555-1234, 212-555-1234, +1 212 555 1234, 2125551234
    regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    validator: isValidPhone,
    severity: "medium",
};
export const PII_EMAIL = {
    type: "pii_email",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    validator: isValidEmail,
    severity: "medium",
};
export function getPiiPatterns(options) {
    const out = [];
    if (options.ssn) {
        out.push(PII_SSN);
        out.push(PII_SSN_NO_DASHES);
    }
    if (options.creditCard) {
        out.push(PII_CREDIT_CARD);
    }
    if (options.phone) {
        out.push(PII_PHONE);
    }
    if (options.email) {
        out.push(PII_EMAIL);
    }
    return out;
}
//# sourceMappingURL=pii.js.map