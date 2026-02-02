/**
 * API key patterns (aligned with OpenClaw src/logging/redact.ts).
 */
export const API_KEY_PATTERNS = [
    // OpenAI keys (sk-proj-*, sk-*)
    { type: "api_key_sk", regex: /\b(sk-[A-Za-z0-9_-]{8,})\b/g, severity: "high" },
    // Anthropic keys (sk-ant-*)
    { type: "api_key_anthropic", regex: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g, severity: "high" },
    // GitHub PATs
    { type: "api_key_ghp", regex: /\b(ghp_[A-Za-z0-9]{20,})\b/g, severity: "high" },
    { type: "api_key_github_pat", regex: /\b(github_pat_[A-Za-z0-9_]{20,})\b/g, severity: "high" },
    // GitHub OAuth tokens
    { type: "api_key_gho", regex: /\b(gho_[A-Za-z0-9]{20,})\b/g, severity: "high" },
    // GitHub App tokens
    { type: "api_key_ghu", regex: /\b(ghu_[A-Za-z0-9]{20,})\b/g, severity: "high" },
    { type: "api_key_ghs", regex: /\b(ghs_[A-Za-z0-9]{20,})\b/g, severity: "high" },
    // Slack tokens
    { type: "api_key_xox", regex: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, severity: "high" },
    { type: "api_key_xapp", regex: /\b(xapp-[A-Za-z0-9-]{10,})\b/g, severity: "high" },
    // Google API keys
    { type: "api_key_google", regex: /\b(AIza[0-9A-Za-z\-_]{20,})\b/g, severity: "high" },
    // Groq keys
    { type: "api_key_gsk", regex: /\b(gsk_[A-Za-z0-9_-]{10,})\b/g, severity: "high" },
    // npm tokens
    { type: "api_key_npm", regex: /\b(npm_[A-Za-z0-9]{10,})\b/g, severity: "high" },
    // Telegram bot tokens
    { type: "api_key_telegram", regex: /\b(\d{6,}:[A-Za-z0-9_-]{20,})\b/g, severity: "high" },
    // Perplexity keys
    { type: "api_key_pplx", regex: /\b(pplx-[A-Za-z0-9_-]{10,})\b/g, severity: "high" },
    // Stripe keys (live and test)
    { type: "api_key_stripe_live", regex: /\b(sk_live_[A-Za-z0-9]{20,})\b/g, severity: "critical" },
    { type: "api_key_stripe_test", regex: /\b(sk_test_[A-Za-z0-9]{20,})\b/g, severity: "high" },
    { type: "api_key_stripe_pk", regex: /\b(pk_(?:live|test)_[A-Za-z0-9]{20,})\b/g, severity: "medium" },
    { type: "api_key_stripe_rk", regex: /\b(rk_(?:live|test)_[A-Za-z0-9]{20,})\b/g, severity: "high" },
    // Twilio
    { type: "api_key_twilio_sid", regex: /\b(AC[a-f0-9]{32})\b/g, severity: "high" },
    { type: "api_key_twilio_auth", regex: /\b(SK[a-f0-9]{32})\b/g, severity: "high" },
    // SendGrid
    { type: "api_key_sendgrid", regex: /\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b/g, severity: "high" },
    // Mailgun
    { type: "api_key_mailgun", regex: /\b(key-[A-Za-z0-9]{32})\b/g, severity: "high" },
    // Postmark
    { type: "api_key_postmark", regex: /\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b/gi, severity: "medium" },
    // Discord bot tokens (base64-ish format)
    { type: "api_key_discord", regex: /\b([MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b/g, severity: "high" },
    // Heroku API key
    { type: "api_key_heroku", regex: /\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b/gi, severity: "medium" },
    // Datadog API key
    { type: "api_key_datadog", regex: /\b(dd[a-z]{1,2}_[A-Za-z0-9]{32,})\b/g, severity: "high" },
    // Sentry DSN
    { type: "api_key_sentry", regex: /\b(https:\/\/[a-f0-9]{32}@[a-z0-9.]+\.sentry\.io\/\d+)\b/gi, severity: "high" },
    // Supabase
    { type: "api_key_supabase", regex: /\b(sbp_[A-Za-z0-9]{40,})\b/g, severity: "high" },
    // Vercel
    { type: "api_key_vercel", regex: /\b(vercel_[A-Za-z0-9_-]{20,})\b/gi, severity: "high" },
    // Netlify
    { type: "api_key_netlify", regex: /\b(nfp_[A-Za-z0-9]{40,})\b/g, severity: "high" },
    // Linear
    { type: "api_key_linear", regex: /\b(lin_api_[A-Za-z0-9]{40,})\b/g, severity: "high" },
    // Notion
    { type: "api_key_notion", regex: /\b(secret_[A-Za-z0-9]{40,})\b/g, severity: "high" },
    // Airtable
    { type: "api_key_airtable", regex: /\b(key[A-Za-z0-9]{14})\b/g, severity: "high" },
    // Figma
    { type: "api_key_figma", regex: /\b(figd_[A-Za-z0-9_-]{40,})\b/g, severity: "high" },
    // Mapbox
    { type: "api_key_mapbox", regex: /\b(pk\.[A-Za-z0-9]{60,})\b/g, severity: "medium" },
    { type: "api_key_mapbox_sk", regex: /\b(sk\.[A-Za-z0-9]{60,})\b/g, severity: "high" },
    // Firebase
    { type: "api_key_firebase", regex: /\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})\b/g, severity: "high" },
];
//# sourceMappingURL=api-keys.js.map