# Configuration

PromptShield loads configuration from:

```text
~/.promptshield/config.yaml
```

If the file does not exist, PromptShield starts with defaults and creates required local directories as needed.

## Full Example

```yaml
port: 8080
log_file: ~/.promptshield/audit.log

mitm:
  enabled: true
  domains:
    - api.openai.com
    - chat.openai.com

sanitizer:
  enabled: true
  types:
    - email
    - phone
    - api_key
  confidence_threshold: 0.8
  max_replacements: 100

rules:
  - id: allow-all
    action: allow

  - id: block-openai
    match:
      host_contains: openai.com
    action: block

  - id: mitm-openai
    match:
      host_contains: openai.com
    action: mitm
```

## Sections

### `port`

- TCP port for the local proxy listener.
- Default: `8080`.

### `log_file`

- Destination for JSONL audit logs.
- Supports `~/` home expansion.
- Default: `~/.promptshield/audit.log`.

### `mitm`

Controls TLS interception behavior.

- `enabled`: global switch for MITM behavior
- `domains`: allowlist of domains eligible for interception

If `enabled: false`, PromptShield stays in tunnel behavior for HTTPS.

### `sanitizer`

Controls content redaction during inspected traffic.

- `enabled`: turn sanitization on/off
- `types`: detector types to apply (for example: `email`, `phone`, `api_key`, `jwt`)
- `confidence_threshold`: optional detection threshold
- `max_replacements`: upper bound for redactions in one payload

### `rules`

Ordered policy rules evaluated top-to-bottom. Each rule includes:

- `id`: rule identifier
- `match`: host match definition (`host` or `host_contains`)
- `action`: `allow`, `block`, or `mitm`

A common baseline is a final catch-all allow rule.

## Rule Examples

### Block a domain

```yaml
rules:
  - id: block-openai
    match:
      host_contains: openai.com
    action: block
```

### Allow only specific hosts

```yaml
rules:
  - id: allow-anthropic
    match:
      host: api.anthropic.com
    action: allow

  - id: block-rest
    action: block
```

### Require MITM for selected domains

```yaml
mitm:
  enabled: true
  domains:
    - api.openai.com

rules:
  - id: mitm-openai
    match:
      host: api.openai.com
    action: mitm

  - id: allow-others
    action: allow
```
