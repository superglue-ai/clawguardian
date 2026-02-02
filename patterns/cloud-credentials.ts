/**
 * Cloud provider credential patterns (AWS, GCP, Azure).
 */

import type { PatternSpec } from "./api-keys.js";

export const CLOUD_CREDENTIAL_PATTERNS: PatternSpec[] = [
  // AWS Access Key ID - always starts with AKIA, ABIA, ACCA, ASIA
  { type: "aws_access_key", regex: /\b(A[KBS]IA[0-9A-Z]{16})\b/g, severity: "high" },
  // AWS Secret Key - only match when near AWS context keywords
  {
    type: "aws_secret_key",
    regex: /(?:aws_secret|secret_access_key|AWS_SECRET)[^\w]*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    severity: "high",
  },
  // GCP API keys - exactly 39 chars (AIza + 35 alphanumeric/dash/underscore)
  { type: "gcp_api_key", regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g, severity: "high" },
  // Azure connection strings
  {
    type: "azure_connection_string",
    regex: /(?:DefaultEndpointsProtocol|AccountKey|AccountName)=[^;]+/gi,
    severity: "high",
  },
  // Azure Storage Account Key (base64, 88 chars)
  {
    type: "azure_storage_key",
    regex: /(?:AccountKey|azure_storage_key)[^\w]*[=:]\s*["']?([A-Za-z0-9/+=]{86,88})["']?/gi,
    severity: "high",
  },
];
