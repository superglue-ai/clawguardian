/**
 * Validation utilities for PII detection.
 * Uses external libraries for robust validation after regex matching.
 */
import type { CountryCode } from "libphonenumber-js";
/**
 * Validate a credit card number using the Luhn algorithm.
 * This catches false positives from regex (random 16-digit numbers).
 * Also rejects obviously fake numbers like all zeros or all same digit.
 */
export declare function isValidCreditCard(candidate: string): boolean;
/**
 * Validate a phone number using libphonenumber-js.
 * Uses strict validation to ensure the number is actually valid.
 */
export declare function isValidPhone(candidate: string, defaultCountry?: CountryCode): boolean;
/**
 * Validate an SSN format (basic structure check).
 * SSNs have specific rules: area (001-899, not 666), group (01-99), serial (0001-9999).
 */
export declare function isValidSSN(candidate: string): boolean;
/**
 * Validate an email address (basic RFC-compliant check).
 * More permissive than strict RFC 5322 but catches obvious non-emails.
 */
export declare function isValidEmail(candidate: string): boolean;
//# sourceMappingURL=validators.d.ts.map