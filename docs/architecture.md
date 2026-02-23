# Architecture

Velar is a local, host-based proxy designed to enforce security controls for outbound AI/LLM traffic.

## Components

### Proxy

The proxy accepts HTTP and HTTPS requests from local applications and developer tools. It is the entry point for all traffic processing.

### MITM Layer

For configured domains, Velar can terminate and re-establish TLS to inspect HTTP content. For non-MITM traffic, HTTPS requests are tunneled with CONNECT.

### Policy Engine

The policy engine evaluates ordered rules and returns one of three actions:

- `allow`: pass traffic through
- `block`: deny request
- `mitm`: require TLS interception for matching hosts

### Sanitizer

When inspection is active, Velar can sanitize request/response data by redacting configured sensitive data types (for example, emails, phone numbers, API keys, JWT-like tokens).

### Audit Log

Every processed request produces structured JSONL audit records for observability, debugging, and forensic workflows.

### CLI

`velar` manages lifecycle and operations:

- daemon start/stop/status/logs
- local CA initialization
- system proxy enable/disable/status (macOS)

## Request Flow

1. A client sends request traffic to Velar.
2. Velar classifies request target (host/domain).
3. Policy engine evaluates matching rules in order.
4. Decision is applied:
   - `block` → return denial response
   - `allow` → forward directly (or tunnel for HTTPS)
   - `mitm` → intercept TLS for configured domains
5. If inspection is active and sanitizer is enabled, sensitive patterns are redacted.
6. Velar emits an audit event with request metadata, policy decision, and sanitization results.

## Modes

### Tunnel mode

- No HTTPS decryption.
- CONNECT requests are forwarded as encrypted tunnels.
- Lowest inspection depth.

### MITM mode

- HTTPS decryption enabled for selected domains.
- Requires trusted local CA certificate.
- Enables content-level sanitization and deeper auditing.

## Why a Local Agent

A local-first security agent provides:

- **privacy**: data stays on-device during control and inspection
- **control**: per-machine policies for real developer workflows
- **low latency**: no mandatory round-trip to external gateways
