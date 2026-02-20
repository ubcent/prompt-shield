# PromptShield — AI Traffic Firewall for Developers

PromptShield is a local proxy that monitors, controls, and sanitizes AI/LLM traffic.

## Problem

Developers regularly send prompts, code snippets, and tokens to services such as ChatGPT, Copilot, and other LLM APIs. Without an explicit control point, teams have limited visibility into what leaves developer machines, and limited ability to enforce policy before data is sent. This creates practical security and compliance risks:

- accidental leakage of secrets or internal code
- unmanaged access to external AI endpoints
- poor auditability for incident response or governance

## Solution

PromptShield runs locally as a security proxy between developer tools and LLM providers. It can:

- intercept outbound traffic
- apply policy decisions (`allow`, `block`, `mitm`)
- optionally inspect and sanitize request content
- produce structured audit logs for traceability

## Key Features

- HTTP/HTTPS proxy for local AI traffic control
- selective MITM (TLS interception) per configured domains
- policy engine with `allow` / `block` / `mitm` actions
- prompt sanitization for PII and common secret patterns
- JSONL audit logging for security analysis
- system proxy integration on macOS (`psctl proxy on`)

## Architecture (Short)

```text
App → PromptShield → LLM APIs
```

PromptShield consists of four core layers:

- **Proxy layer**: receives HTTP/HTTPS traffic from local clients
- **Policy engine**: evaluates host-based rules and decides action
- **Sanitizer**: redacts configured sensitive data patterns during inspected flows
- **Audit logger**: stores request events as JSONL records

For deeper details, see [docs/architecture.md](docs/architecture.md).

## Quick Start

### 1) Build

```bash
go build ./cmd/psd
go build ./cmd/psctl
```

### 2) Generate local CA

```bash
./psctl ca init
```

### 3) Install certificate (macOS)

1. Open the generated certificate:
   ```bash
   open ~/.promptshield/ca/cert.pem
   ```
2. Add it to **Keychain Access**.
3. Open the certificate trust settings.
4. Set **When using this certificate** to **Always Trust**.

### 4) Start proxy

```bash
./psctl start
```

Default listener:

```text
http://localhost:8080
```

### 5) Enable system proxy (macOS)

```bash
./psctl proxy on
```

You can verify status with:

```bash
./psctl proxy status
```

## Demo

```bash
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer sk-123..."
```

When your system or shell proxy points to PromptShield:

- the request is routed through the local proxy
- policy rules are evaluated for `api.openai.com`
- sensitive values can be masked in logged metadata

## Example Output

Example audit event (JSONL):

```json
{
  "ts": "2026-01-14T10:22:31Z",
  "method": "POST",
  "host": "api.openai.com",
  "path": "/v1/chat/completions",
  "decision": "mitm",
  "sanitized": true,
  "sanitized_items": ["api_key", "email"],
  "status": 200,
  "latency_ms": 241
}
```

## Configuration

See [docs/configuration.md](docs/configuration.md) for full configuration reference and policy examples.

## Testing

Запустить все тесты одной командой:

```bash
make test
```

Эта команда:
1. 🐳 Собирает Docker образы для proxy и echo сервисов
2. ⏳ Ждет, пока сервисы пройдут healthcheck
3. 🧪 Запускает все тесты (`go test ./...`)
4. 🧹 Автоматически останавливает контейнеры

### Структура тестов

Все тесты находятся рядом с кодом:
- `internal/*/` - unit тесты в `*_test.go` файлах
- `internal/integration/` - интеграционные тесты с proxy и echo

### Локальное тестирование

```bash
# Запустить тесты локально (без Docker)
go test ./...

# С проверкой race conditions
go test -race ./...
```

**Примечание:** Integration тесты требуют переменные окружения `PROXY_ADDR` и `ECHO_ADDR`.

## Security

- MITM inspection is optional and domain-scoped.
- Processing is local to your machine.
- PromptShield does not require remote control-plane services for core operation.

Read the full security guidance in [docs/security.md](docs/security.md).

## Roadmap

- system-level network agent mode (VPN/TUN)
- VS Code extension for developer workflow visibility
- enterprise policy packs, identity integration, and centralized audit shipping

## Disclaimer

PromptShield is a traffic interception tool. You should use it only in environments you trust and understand. Enabling HTTPS interception requires installing and trusting a local CA certificate. This project is intended for local development, security testing, and controlled internal usage.
