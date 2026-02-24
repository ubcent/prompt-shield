# Velar Development Roadmap

## Overview
This directory contains spec-driven development prompts for Velar enhancement. Each prompt describes a self-contained, measurable feature addition.

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

### Phase 4: Provider Ecosystem (P1 - Market Coverage)
9. **[Anthropic & Bedrock Support](./9-anthropic-bedrock-support.md)** 🤖
   - First-class support for Claude API
   - AWS Bedrock multi-model support
   - Estimated effort: 3-4 days

10. **[GitHub Actions Integration](./10-github-actions-integration.md)** 🚀
    - CI/CD secret detection
    - GitHub Marketplace presence
    - Estimated effort: 3-4 days

## Total Estimated Effort
- **Phase 1 (P0 Core)**: 10-15 days
- **Phase 2 (P1 DevEx)**: 5-6 days
- **Phase 3 (P1 Enterprise)**: 7-9 days
- **Phase 4 (P1 Ecosystem)**: 6-8 days
- **Grand Total**: 28-38 days (~5-7 weeks with one developer)

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

### Phase 4 Success (Ecosystem)
- [ ] Anthropic API support validated by users
- [ ] GitHub Action used in 10+ public repos
- [ ] GitHub Marketplace listing published

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
