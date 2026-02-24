# Task: Team Policy Configuration

## Objective
Enable teams to share and enforce common Velar policies via Git repositories or remote URLs.

## Current State
- Each developer has separate local config
- No way to enforce organization-wide policies
- Config drift across team members

## Specification

### Functional Requirements
1. Support remote policy configuration from:
   - Git repository URL: `https://github.com/company/velar-policy.git`
   - HTTPS URL: `https://company.com/velar-policy.yaml`
   - Local file path: `/shared/team-policy.yaml`
2. Merge strategy:
   - Team policy as base
   - Local config overrides specific values
   - Explicit `allow_local_override: false` prevents overrides
3. Policy refresh:
   - Manual: `velar policy refresh`
   - Automatic: check every N minutes (configurable)
   - On daemon start
4. Policy validation:
   - Syntax checking before applying
   - Rollback to previous version on invalid config
5. Audit which policy version is active

### Technical Requirements
1. Implement `internal/policy/remote.go` for remote policy fetching
2. Support Git clone/pull via `git` command or `go-git` library
3. Cache remote policies in `~/.velar/policies/remote/`
4. Add policy merge logic in `internal/policy/merger.go`
5. Store policy metadata: source URL, version, last updated
6. Add versioning to policy files (semantic versioning)

### Acceptance Criteria
- [ ] Remote policy fetches from public Git repo
- [ ] Remote policy fetches from HTTPS URL
- [ ] Local config correctly overrides when allowed
- [ ] Policy refresh works via CLI command
- [ ] Invalid remote policy triggers rollback
- [ ] Audit log records policy source and version
- [ ] Works offline (uses cached policy)
- [ ] All existing tests pass

### Testing Requirements
1. Mock HTTP server for testing HTTPS policy source
2. Mock Git repository for testing Git policy source
3. Test merge logic with various override scenarios
4. Test policy validation and rollback
5. Add tests in `internal/policy/remote_test.go`
6. Update `internal/config/config_test.go` with remote policy scenarios

### Files to Create/Modify
- `internal/policy/remote.go` - NEW: remote policy fetching
- `internal/policy/remote_test.go` - NEW: remote policy tests
- `internal/policy/merger.go` - NEW: policy merge logic
- `internal/policy/merger_test.go` - NEW: merge logic tests
- `internal/config/config.go` - add remote policy config section
- `cmd/velar/main.go` - add `policy refresh` command
- `README.md` - document team policy setup

## Config Example

### Local config.yaml
```yaml
port: 8080
policy:
  remote:
    enabled: true
    source: "https://github.com/myorg/velar-policy.git"
    branch: "main"
    refresh_interval: 60  # minutes
    allow_local_override: true
```

### Remote team-policy.yaml
```yaml
version: "1.2.0"
mitm:
  enabled: true
  domains:
    - api.openai.com
    - api.anthropic.com
sanitizer:
  enabled: true
  types:
    - email
    - phone
    - api_key
    - aws_key
  max_replacements: 20
rules:
  - id: block-public-ai
    match:
      host_contains: "api.openai.com"
    action: mitm
    allow_local_override: false  # team enforces this
  - id: allow-internal
    match:
      host_contains: "internal.company.com"
    action: allow
```

## CLI Commands

### Fetch remote policy
```bash
velar policy refresh
# Output: Fetched policy v1.2.0 from https://github.com/myorg/velar-policy.git
```

### Show current policy
```bash
velar policy show
# Output:
# Source: https://github.com/myorg/velar-policy.git
# Version: 1.2.0
# Last Updated: 2024-01-15 14:30:00
# Local Overrides: 2
```

### Validate policy
```bash
velar policy validate
# Output: Policy is valid ✓
```

## Merge Logic

```
Remote Policy (base)
  ↓
  + Local Config (overrides where allowed)
  ↓
  = Effective Policy
```

### Example Merge
```yaml
# Remote
sanitizer:
  types: [email, phone]
  max_replacements: 10

# Local (override)
sanitizer:
  types: [email, phone, api_key]  # added api_key
  max_replacements: 10  # unchanged

# Effective
sanitizer:
  types: [email, phone, api_key]
  max_replacements: 10
```

## Non-Goals
- Policy signing or encryption
- Multi-source policy aggregation
- Complex policy DSL or expressions
- Real-time policy push from server
