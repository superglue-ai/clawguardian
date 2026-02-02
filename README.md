# ClawGuardian

Security plugin for OpenClaw that detects and filters sensitive data in tool calls.

## Features

- **Secret Detection**: API keys, tokens, cloud credentials, private keys
- **PII Filtering**: SSN, credit cards, email addresses, phone numbers
- **Destructive Command Protection**: rm -rf, git reset --hard, DROP TABLE, sudo, etc.
- **Configurable Actions**: block, redact, confirm (user approval), agent-confirm (agent acknowledgment), warn, log
- **Severity-Based Rules**: Different actions for critical/high/medium/low severity
- **Allowlists**: Skip detection for specific tools, patterns, or sessions
- **Custom Patterns**: Add your own regex patterns

## Installation

```bash
# From the openclaw root directory
cd extensions/clawguardian
npm install --omit=dev
```

## Configuration

Add to your OpenClaw config (`~/.openclaw/config.yaml`):

```yaml
plugins:
  clawguardian:
    # Enable/disable detection categories
    secrets:
      enabled: true
      action: redact  # default action
      severityActions:
        critical: block      # private keys
        high: redact         # API keys, tokens
        medium: redact
        low: warn
      categories:
        apiKeys: true
        cloudCredentials: true
        privateKeys: true
        tokens: true

    pii:
      enabled: true
      action: redact
      severityActions:
        critical: block
        high: redact         # SSN, credit cards
        medium: warn         # email, phone
        low: warn
      categories:
        ssn: true
        creditCard: true
        email: true          # warn only by default
        phone: true          # warn only by default

    destructive:
      enabled: true
      action: confirm        # requires user approval for exec tools
      severityActions:
        critical: block      # rm -rf /, DROP DATABASE, dd
        high: confirm        # rm -rf, git reset --hard
        medium: confirm      # kill, git checkout
        low: warn            # git branch -d
      categories:
        fileDelete: true
        gitDestructive: true
        sqlDestructive: true
        systemDestructive: true
        processKill: true
        networkDestructive: true
        privilegeEscalation: true

    # Skip detection for specific cases
    allowlist:
      tools:
        - "safe_tool"
      patterns:
        - "sk-test-.*"       # test API keys
      sessions:
        - "trusted-session"

    # Add custom detection patterns
    customPatterns:
      - name: internal_token
        pattern: "INTERNAL_[A-Z0-9]{32}"
        severity: high
        action: block

    logging:
      logDetections: true
      logLevel: warn
```

## Actions

| Action | Description |
|--------|-------------|
| `block` | Reject the tool call entirely |
| `redact` | Replace sensitive data with `[REDACTED]` |
| `confirm` | Require user approval (exec/bash tools only, via OpenClaw's approval flow) |
| `agent-confirm` | Block until agent retries with `_clawguardian_confirm: true` in params |
| `warn` | Log warning but allow execution |
| `log` | Silent logging only |

## Severity Levels

| Severity | Secrets | PII | Destructive | Default Action |
|----------|---------|-----|-------------|----------------|
| Critical | Private keys | - | rm -rf /, DROP DATABASE, dd | `block` |
| High | API keys, tokens, cloud creds | SSN, credit cards | rm -rf, git reset --hard, sudo | `redact` / `confirm` |
| Medium | - | Email, phone | kill, git checkout | `warn` / `confirm` |
| Low | - | - | git branch -d | `warn` |

## Agent Confirmation

When a tool call is blocked with `agent-confirm`, the agent receives a message instructing it to retry with the `_clawguardian_confirm: true` parameter:

```json
{
  "tool": "some_tool",
  "params": {
    "data": "sensitive content",
    "_clawguardian_confirm": true
  }
}
```

ClawGuardian injects instructions into the agent's system prompt explaining this mechanism.

## API

### Hooks

ClawGuardian registers three hooks:

1. **`before_agent_start`** (priority 50): Injects ClawGuardian context into the system prompt
2. **`before_tool_call`** (priority 100): Filters tool inputs, detects destructive commands
3. **`tool_result_persist`** (priority 100): Redacts/blocks sensitive data in tool outputs

### Detection Functions

```typescript
import { detectSecret } from "clawguardian/utils/matcher";
import { detectDestructive } from "clawguardian/destructive";

// Detect secrets/PII in text
const match = detectSecret(text, config);
// Returns: { type, index, length, severity, category, action } | undefined

// Detect destructive commands
const destructive = detectDestructive(toolName, params);
// Returns: { reason, severity, category } | undefined
```

## Development

```bash
# Run tests
pnpm test extensions/clawguardian/index.test.ts

# Type check
pnpm build

# Lint
pnpm lint
```

## Pattern Categories

### Secrets

- **API Keys**: OpenAI, Anthropic, GitHub, Stripe, AWS, GCP, Azure, Twilio, SendGrid, etc.
- **Cloud Credentials**: AWS access/secret keys, GCP service accounts, Azure storage keys
- **Private Keys**: PEM-encoded RSA/EC/DSA keys
- **Tokens**: Bearer tokens, JWT, session tokens

### PII

- **SSN**: US Social Security Numbers (with and without dashes)
- **Credit Cards**: 13-19 digit card numbers with Luhn validation
- **Email**: Standard email format
- **Phone**: International phone numbers (validated with libphonenumber-js)

### Destructive Commands

- **File Deletion**: rm -rf, find -delete, xargs rm
- **Git**: reset --hard, clean -f, push --force, branch -D
- **SQL**: DROP, TRUNCATE, DELETE without WHERE
- **System**: shutdown, reboot, mkfs, dd
- **Process**: kill -9, pkill, killall
- **Network**: iptables, ufw, firewall-cmd
- **Privilege Escalation**: sudo, doas, su, pkexec

## License

MIT
