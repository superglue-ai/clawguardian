/**
 * Token patterns: Bearer, JWT, env-style assignments, JSON fields, PEM.
 */
export const TOKEN_PATTERNS = [
    { type: "bearer", regex: /\bBearer\s+([A-Za-z0-9._\-+=]{18,})\b/g, severity: "high" },
    {
        type: "authorization_header",
        regex: /Authorization\s*[:=]\s*Bearer\s+([A-Za-z0-9._\-+=]+)/gi,
        severity: "high",
    },
    {
        type: "env_key_token",
        regex: /\b[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)\b\s*[=:]\s*(["']?)([^\s"'\\]+)\1/g,
        severity: "high",
    },
    {
        type: "json_token_field",
        regex: /"(?:apiKey|token|secret|password|passwd|accessToken|refreshToken)"\s*:\s*"([^"]+)"/g,
        severity: "high",
    },
    {
        type: "cli_token_flag",
        regex: /--(?:api[-_]?key|token|secret|password|passwd)\s+(["']?)([^\s"']+)\1/g,
        severity: "high",
    },
];
//# sourceMappingURL=tokens.js.map