# Velar Development Roadmap

## Overview
This directory contains spec-driven development prompts for Velar enhancement. Each prompt describes a self-contained, measurable feature addition.

## Architecture & Threat Coverage

```
┌─────────────────────────────────────────────────────────────────┐
│                    Velar Security Layers                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Layer 1: OUTBOUND PROTECTION (App → AI Provider)               │
│  ┌──────────────────────────────────────────────────────┐       │
│  │ #1  Streaming Response Modification                 │       │
│  │ #2  Enhanced Secret Detection                       │       │
│  │ #5  Audit Log Rotation                              │       │
│  │ Features: Mask secrets/PII, restore in responses    │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                   │
│  Layer 2: COMPLIANCE & AUDIT (Enterprise Requirements)           │
│  ┌──────────────────────────────────────────────────────┐       │
│  │ #7  Team Policy Configuration                       │       │
│  │ #8  Audit Export to SIEM                            │       │
│  │ #14 Cryptographic Audit Verification (NEW!)         │       │
│  │ Features: Policies, centralized logging, integrity  │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                   │
│  Layer 3: AGENT SECURITY (Toxic Flow + Vector Protection)       │
│  ┌──────────────────────────────────────────────────────┐       │
│  │ #15 Scoped Permissions & Toxic Flow Detection       │       │
│  │ #16 Vector Firewall: RAG Security (NEW!)            │       │
│  │ Features: Token scopes, prompt injection detection  │       │
│  │           MCP security, tenant-aware vector access  │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                   │
│  Layer 4: ECOSYSTEM & DevEx (Adoption)                          │
│  ┌──────────────────────────────────────────────────────┐       │
│  │ #3  Model Download Command                          │       │
│  │ #4  CLI Stats Command                               │       │
│  │ #6  VSCode Extension                                │       │
│  │ #9  Anthropic & Bedrock Support                     │       │
│  │ #10 GitHub Actions Integration                      │       │
│  │ Features: Easy setup, IDE integration, monitoring   │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

THREAT COVERAGE MAPPING:
  Accidental data leaks        → Layer 1 (masking)
  Compliance violations        → Layer 2 (audit + crypto)
  Prompt injection attacks     → Layer 3 (toxic flow detection)
  Excessive agency / "sudo AI" → Layer 3 (scoped permissions)
  Insider threats              → Layer 2 (cryptographic signing)
  Cross-tenant RAG leakage     → Layer 3 (vector firewall)
  Poisoned vector injection    → Layer 3 (vector firewall)
  Model extraction via RAG     → Layer 3 (vector firewall)
```

## Principles
1. **Spec-driven**: Each task has clear specifications and acceptance criteria
2. **Testable**: Every change must include tests
3. **Incremental**: Features build on each other progressively
4. **Measurable**: Success is defined by concrete metrics

## Implementation Order

### Phase 1: Core Functionality (P0 - Critical)
1. **[Streaming Response Modification](./1-streaming-response-modification.md)** ⚡ HIGH IMPACT
   - Enable placeholder restoration in streaming responses
   - Critical for real-world usage with AI providers
   - Estimated effort: 2-3 days

2. **[Enhanced Secret Detection](./5-enhanced-secret-detection.md)** 🔐 HIGH IMPACT
   - Expand beyond basic PII to AWS/GCP/Azure credentials
   - Detect private keys, database URLs, high-entropy secrets
   - Estimated effort: 3-4 days

3. **[Model Download Command](./12-model-download-command.md)** 📦 HIGH VALUE
   - Automated NER model management
   - Easy setup for advanced detection
   - Estimated effort: 2-3 days

4. **[CLI Stats Command](./11-cli-stats-command.md)** 📊 HIGH VALUE
   - Terminal-based monitoring and statistics
   - Lightweight alternative to web UI
   - Estimated effort: 2-3 days

5. **[Audit Log Rotation](./13-audit-log-rotation.md)** 🔄 HIGH VALUE
   - Automatic log rotation and cleanup
   - Prevent disk space exhaustion
   - Estimated effort: 1-2 days

### Phase 2: Developer Experience (P1 - Adoption)
6. **[VSCode Extension](./6-vscode-extension.md)** 💻 HIGH VALUE
   - IDE integration with inline warnings
   - Major driver for developer adoption
   - Estimated effort: 5-6 days

### Phase 3: Team & Enterprise (P1 - B2B Readiness)
7. **[Team Policy Configuration](./7-team-policies.md)** 👥
   - Remote policy management via Git
   - Essential for team/enterprise use cases
   - Estimated effort: 3-4 days

8. **[Audit Export to SIEM](./8-audit-export-siem.md)** 📡
   - Splunk/Elasticsearch/Datadog integration
   - Enterprise compliance requirement
   - Estimated effort: 4-5 days

9. **[Cryptographic Audit Verification](./14-cryptographic-audit-verification.md)** 🔐
   - Tamper-evident, verifiable audit logs
   - HMAC-SHA256 & Ed25519 signing
   - Chain-of-custody verification
   - Estimated effort: 4-5 days

### Phase 4: Provider Ecosystem (P1 - Market Coverage)
10. **[Anthropic & Bedrock Support](./9-anthropic-bedrock-support.md)** 🤖
    - First-class support for Claude API
    - AWS Bedrock multi-model support
    - Estimated effort: 3-4 days

11. **[GitHub Actions Integration](./10-github-actions-integration.md)** 🚀
    - CI/CD secret detection
    - GitHub Marketplace presence
    - Estimated effort: 3-4 days

### Phase 5: Agent Security (P2 - Advanced)
12. **[Scoped Permissions & Toxic Flow Detection](./15-scoped-permissions-toxic-flow.md)** 🛡️ CRITICAL
    - "sudo for AI tools": scoped, expiring permissions for agents
    - Prompt injection detection & excessive agency protection
    - Deterministic audit trails for MCP/tool access
    - Estimated effort: 6-8 days

13. **[Vector Firewall: RAG Security & Multi-Tenant Authorization](./16-vector-firewall-rag-security.md)** 🔍 CRITICAL
    - Tenant-aware vector database access control
    - Poisoned vector detection (persistent prompt injection)
    - Cross-tenant leakage prevention in RAG systems
    - Estimated effort: 6-8 days

## Total Estimated Effort
- **Phase 1 (P0 Core)**: 10-15 days
- **Phase 2 (P1 DevEx)**: 5-6 days
- **Phase 3 (P1 Enterprise)**: 11-14 days
- **Phase 4 (P1 Ecosystem)**: 6-8 days
- **Phase 5 (P2 Agent Security)**: 12-16 days (2 critical features)
- **Grand Total**: 44-59 days (~8-11 weeks with one developer)

## Success Metrics

### Phase 1 Success (Core)
- [ ] Streaming works for 99% of OpenAI/Anthropic requests
- [ ] AWS key detection rate > 95%
- [ ] False positive rate < 5%
- [ ] Model download success rate > 98%
- [ ] CLI stats command used in 80%+ of installations
- [ ] Log rotation works reliably with no data loss

### Phase 2 Success (DevEx)
- [ ] VSCode extension has < 100ms activation time
- [ ] 50+ GitHub stars on extension repo
- [ ] 200+ active VSCode extension users

### Phase 3 Success (Enterprise)
- [ ] 3+ teams using remote policies
- [ ] SIEM integration with at least 2 providers tested
- [ ] 90% policy sync success rate
- [ ] Audit verification command working reliably
- [ ] Zero tampered log detections in deployments (clean audit trail)

### Phase 4 Success (Ecosystem)
- [ ] Anthropic API support validated by users
- [ ] GitHub Action used in 10+ public repos
- [ ] GitHub Marketplace listing published

### Phase 5 Success (Agent Security)
- [ ] Agents can request and use scoped tokens
- [ ] Permission enforcement prevents unauthorized tool access
- [ ] Prompt injection detection > 90% accuracy
- [ ] Toxic flow events logged in audit trail
- [ ] Vector queries auto-filtered by tenant
- [ ] Poisoned vectors detected with > 85% accuracy
- [ ] Cross-tenant RAG leakage prevented
- [ ] Zero known prompt injection bypasses in testing

## How to Use These Prompts

### For AI Assistants (Claude, GPT-4, etc.)
```
Read the file prompts/X-task-name.md and implement the feature according to the specification.

Requirements:
1. Follow the functional and technical requirements exactly
2. Implement all acceptance criteria
3. Write tests for all new functionality
4. Update existing tests that are affected
5. Ensure all tests pass before finishing
6. Update documentation as specified

Do not:
- Skip tests
- Ignore acceptance criteria
- Add features not in the spec
- Break existing functionality
```

### For Human Developers
1. Read the spec completely before starting
2. Set up a feature branch: `git checkout -b feature/streaming-response`
3. Implement according to spec with TDD approach
4. Check off acceptance criteria as you go
5. Run full test suite before committing
6. Update the spec if you discover issues

## Contributing

If you find issues with these specs or want to propose new features:
1. Open an issue describing the problem/feature
2. Wait for discussion and approval
3. Create a new numbered prompt file
4. Submit PR with the new spec

## Notes
- Specs are living documents - update them as implementation reveals edge cases
- Each task should remain independently completable
- Dependencies between tasks are noted in individual specs
- Estimated efforts assume familiarity with Go and the Velar codebase

## Feature Dependencies

### Dependency Graph
```
Phase 1 (Core)
  ├─ Streaming Response Modification (independent)
  ├─ Enhanced Secret Detection (independent)
  ├─ Model Download Command (independent)
  ├─ CLI Stats Command (independent)
  └─ Audit Log Rotation (depends on: audit system)

Phase 2 (DevEx)
  └─ VSCode Extension (depends on: #1, #2, #5)

Phase 3 (Enterprise)
  ├─ Team Policy Configuration (independent)
  ├─ Audit Export to SIEM (depends on: audit system)
  └─ Cryptographic Audit Verification (depends on: audit system)

Phase 4 (Ecosystem)
  ├─ Anthropic & Bedrock Support (independent)
  └─ GitHub Actions Integration (independent)

Phase 5 (Agent Security)
  ├─ Scoped Permissions & Toxic Flow (depends on: #14)
  └─ Vector Firewall (depends on: #14, #15)
     └─ Integration: Uses audit signing from #14
     └─ Integration: Cross-checks with toxic flow detector from #15
```

### Critical Path for MVP (Minimum Viable Product)
**P0 Must-Haves** → **P1 Enterprise** → **P2 Agent Security**
- #1: Streaming Response (core feature)
- #2: Enhanced Secrets (core security)
- #5: Audit Log Rotation (operational stability)
- #14: Cryptographic Audit (compliance + enabler for #15, #16)
- #15: Scoped Permissions (agent safety)
- #16: Vector Firewall (RAG security)

Estimated MVP effort: **26-32 days** (focused on essential features)

### Recommended Implementation Path
For maximum impact and dependency management:
1. **Phase 1-2** (all core features, 15-21 days)
2. **Task #14** (cryptographic audit, 4-5 days) ← Required by #15, #16
3. **Task #15** (toxic flow detection, 6-8 days) ← Required by #16
4. **Task #16** (vector firewall, 6-8 days)
5. **Phase 3-4** (enterprise + ecosystem, 12-16 days)


