# PromptShield

PromptShield is a local security agent for AI/LLM traffic with:

- local HTTP/HTTPS proxy
- selective MITM interception
- policy engine (allow/block/mitm)
- request/response sanitizer
- JSONL audit logging

## 🚀 Quick Start

### 1. Установка

```bash
git clone <repo-url>
cd promptshield
go build ./cmd/psd
go build ./cmd/psctl
```

### 2. Генерация root CA

```bash
./psctl ca init
```

### 3. Установка сертификата (macOS)

```bash
open ~/.promptshield/ca/cert.pem
```

Дальше:

- добавить сертификат в Keychain
- выбрать сертификат и установить Trust = **Always Trust**

### 4. Запуск proxy

```bash
./psctl start
```

По умолчанию proxy доступен на:

```text
http://localhost:8080
```

При запуске `psctl start` выводит:

```text
PromptShield started
Proxy: http://localhost:8080
MITM: enabled|disabled
Sanitizer: enabled|disabled
Log file: ~/.promptshield/audit.log
```

### 5. Настройка proxy

#### Временная (через env)

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
```

#### Или в браузере

- System Settings → Network → Proxy

### 6. Проверка (без MITM)

```bash
curl -x http://localhost:8080 https://example.com
```

### 7. Проверка MITM

```bash
curl -x http://localhost:8080 https://api.openai.com -k
```

Ожидается:

- proxy видит HTTP-запрос после расшифровки TLS
- запрос попадает в audit log

### 8. Проверка sanitizer

```bash
curl -x http://localhost:8080 https://example.com \
  -d '{"email":"test@example.com"}'
```

Ожидается:

- email маскируется sanitizer-ом
- в audit появляется `sanitized_items`

### 9. Просмотр логов

```bash
./psctl logs
```

## 🧪 Demo scenario

1. Включите правило block для `openai.com` в `~/.promptshield/config.yaml`:

```yaml
rules:
  - id: block-openai
    match:
      host_contains: openai.com
    action: block
```

2. Выполните запрос:

```bash
curl -x http://localhost:8080 https://api.openai.com
```

3. Ожидайте ответ `403` от proxy.

## ⚙️ Config example

```yaml
port: 8080
log_file: ~/.promptshield/audit.log

mitm:
  enabled: true
  domains:
    - api.openai.com
    - example.com

sanitizer:
  enabled: true

rules:
  - id: block-openai
    match:
      host_contains: openai.com
    action: block
```

Config path: `~/.promptshield/config.yaml`.

## 🧾 CLI

```bash
./psctl start
./psctl status
./psctl logs
./psctl ca init
./psctl ca print
```

- `start` — запускает proxy как daemon.
- `status` — показывает, запущен ли proxy, порт, состояние MITM/sanitizer.
- `logs` — tail audit log (`~/.promptshield/audit.log`).
- `ca init` — генерирует root CA в `~/.promptshield/ca/`.
- `ca print` — печатает путь к сертификату и короткую инструкцию по установке.

## 🛠️ Make targets

```bash
make build
make run
make test
```

## 📓 Audit log

- файл: `~/.promptshield/audit.log`
- создаётся автоматически
- формат: JSONL (одна JSON запись на строку)

## ⚠️ Troubleshooting

### HTTPS не работает

- проверьте, что root CA установлен
- проверьте trust settings в системе/браузере

### Proxy не используется

- проверьте `HTTP_PROXY` и `HTTPS_PROXY`
- проверьте системные proxy-настройки

### MITM не срабатывает

- проверьте `mitm.enabled: true`
- проверьте `mitm.domains`
- проверьте, что домен запроса совпадает

### Debug

```bash
LOG_LEVEL=debug ./psctl start
```
