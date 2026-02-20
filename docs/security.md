# Security

## What PromptShield Does

PromptShield intercepts outbound HTTP/HTTPS traffic sent through the local proxy endpoint. When configured, it can decrypt HTTPS traffic for selected domains using local TLS interception (MITM).

## Trust Model

PromptShield is designed as a local-only control point:

- runs on the user machine
- is configured by the user/team
- does not require external PromptShield-managed servers for core processing

This model gives developers direct visibility and control over outbound AI traffic.

## Risks and Trade-offs

### Local CA trust requirement

MITM mode requires installing and trusting a local CA certificate. Any process that trusts that CA may accept certificates issued by PromptShield.

### Sensitive data visibility

By design, a proxy that inspects traffic can see sensitive data. Treat PromptShield host access, config files, and logs as sensitive assets.

### Misconfiguration risk

Broad MITM scopes or permissive rules can create unexpected interception behavior.

## Recommended Practices

- Use PromptShield only on trusted, managed machines.
- Prefer minimal MITM scope (specific domains only).
- Review and version-control policy configuration when possible.
- Protect `~/.promptshield` permissions and audit logs.
- Disable MITM when deep inspection is not required.
- Rotate and remove local CA trust when decommissioning.

## Operational Notes

- PromptShield is intended for local development and controlled security testing.
- Before production-like usage, perform security review, threat modeling, and policy validation aligned with your organization requirements.
