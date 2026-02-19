# PromptShield

PromptShield is a local security agent for AI/LLM traffic. This MVP provides:

- local forward proxy (HTTP + HTTPS CONNECT tunnel)
- request classifier (OpenAI / Anthropic / Unknown)
- policy engine (allow / block by host)
- JSONL audit logging
- daemon (`psd`) and CLI (`psctl`)

## Project layout

```text
promptshield/
  cmd/
    psd/        # daemon
    psctl/      # CLI
  internal/
    proxy/      # HTTP/HTTPS proxy
    policy/     # rules engine
    audit/      # logging
    classifier/ # AI/LLM service classifier
    config/     # config loading
  pkg/
```

## Configuration

Config file path: `~/.promptshield/config.yaml`

Example:

```yaml
port: 8080
log_file: ~/.promptshield/audit.log
rules:
  - id: block-openai
    match:
      host_contains: openai.com
    action: block
  - id: mitm-openai
    match:
      host: api.openai.com
    action: mitm
mitm:
  enabled: true
  domains:
    - api.openai.com
    - chat.openai.com
```

If no config exists, defaults are used:

- port: `8080`
- log_file: `~/.promptshield/audit.log`
- rules: allow all

## Run

Start daemon directly:

```bash
go run ./cmd/psd
```

Or via CLI:

```bash
go run ./cmd/psctl start
```

Check status:

```bash
go run ./cmd/psctl status
```

Show last audit lines:

```bash
go run ./cmd/psctl logs
```

## Use as proxy

Set proxy for a single curl command:

```bash
curl -x http://127.0.0.1:8080 https://example.com
```

For HTTP target:

```bash
curl -x http://127.0.0.1:8080 http://httpbin.org/get
```

## Audit log format

Audit log is JSONL (`~/.promptshield/audit.log`) with fields:

- `timestamp`
- `method`
- `host`
- `path`
- `decision` (`allow`/`block`)
- `reason`

## Notes

- HTTPS defaults to CONNECT tunneling and can selectively enable MITM interception by policy/config.
- MITM internals live in `internal/proxy/mitm` and are isolated from the default tunnel pipeline.
- Daemon supports graceful shutdown on SIGINT/SIGTERM.


## HTTPS interception

1. Generate root CA:

```bash
go run ./cmd/psctl ca init
```

2. Install `~/.promptshield/ca/cert.pem` into your system trust store (for macOS use Keychain Access and trust it).
3. Start proxy and keep `mitm.enabled: true` with domain/rule selection.

MITM is optional and only activates for CONNECT hosts matching both a `mitm` policy action and configured `mitm.domains`. Other HTTPS traffic stays in plain CONNECT tunnel mode.
