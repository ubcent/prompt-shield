# Task: GitHub Actions Integration

## Objective
Create a GitHub Action that runs Velar in CI/CD pipelines to detect secrets in prompts before deployment.

## Current State
- No CI/CD integration
- Secrets can leak to AI providers during automated testing
- No pre-deployment validation

## Specification

### Functional Requirements
1. GitHub Action that:
   - Installs Velar binary
   - Scans files for sensitive data patterns
   - Configures proxy for test runs
   - Reports findings in workflow summary
   - Fails workflow if secrets detected (configurable)
2. Scan modes:
   - File scanning: check prompt templates, configs
   - Proxy mode: intercept AI API calls during tests
   - Both modes simultaneously
3. Reporting:
   - Summary comment on PR with findings
   - Annotations on specific lines with issues
   - SARIF output for GitHub Code Scanning
4. Configuration via action inputs:
   - `mode`: `scan`, `proxy`, or `both`
   - `fail-on-secrets`: `true`/`false`
   - `paths`: files/directories to scan
   - `exclude`: patterns to exclude
   - `types`: secret types to detect

### Technical Requirements
1. Create GitHub Action in `.github/actions/velar/action.yml`
2. Action should:
   - Download Velar binary for runner OS
   - Run in Docker container or direct binary
   - Parse audit logs and generate report
   - Post results to PR via GitHub API
3. Support matrix testing across OS (ubuntu, macos, windows)
4. Minimal external dependencies
5. Fast execution (< 30 seconds for typical repo)

### Acceptance Criteria
- [ ] Action installs and runs on ubuntu-latest
- [ ] Action installs and runs on macos-latest
- [ ] Action installs and runs on windows-latest
- [ ] File scan mode detects secrets in test fixtures
- [ ] Proxy mode intercepts test API calls
- [ ] PR comment shows findings with details
- [ ] Workflow fails when secrets detected and `fail-on-secrets: true`
- [ ] SARIF output uploads to GitHub Code Scanning
- [ ] Published to GitHub Marketplace

### Testing Requirements
1. Test action in example workflow
2. Test with repository containing intentional secrets
3. Test PR comment generation
4. Test SARIF output format
5. Test across all OS runners
6. Add example workflows in `.github/workflows/test-velar-action.yml`

### Files to Create
- `.github/actions/velar/action.yml` - action definition
- `.github/actions/velar/action.js` - action logic (Node.js)
- `.github/actions/velar/scanner.js` - file scanning logic
- `.github/actions/velar/reporter.js` - report generation
- `.github/workflows/test-velar-action.yml` - test workflow
- `docs/github-action.md` - action documentation
- `README.md` - add GitHub Action section

## Action Definition

### action.yml
```yaml
name: 'Velar Security Scan'
description: 'Detect and prevent secrets from leaking to AI providers'
author: 'Velar'
branding:
  icon: 'shield'
  color: 'blue'

inputs:
  mode:
    description: 'Scan mode: scan, proxy, or both'
    required: false
    default: 'scan'
  fail-on-secrets:
    description: 'Fail workflow if secrets detected'
    required: false
    default: 'true'
  paths:
    description: 'Paths to scan (comma-separated)'
    required: false
    default: '.'
  exclude:
    description: 'Patterns to exclude (comma-separated)'
    required: false
    default: 'node_modules,vendor,.git'
  types:
    description: 'Secret types to detect (comma-separated)'
    required: false
    default: 'email,phone,api_key,aws_key,jwt'

outputs:
  secrets-found:
    description: 'Number of secrets found'
  report-url:
    description: 'URL to detailed report'

runs:
  using: 'node20'
  main: 'action.js'
```

## Usage Example

### Workflow
```yaml
name: Security Scan

on:
  pull_request:
    branches: [main]

jobs:
  velar-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Velar scan
        uses: ubcent/velar-action@v1
        with:
          mode: 'scan'
          fail-on-secrets: 'true'
          paths: 'src,tests,prompts'
          types: 'email,api_key,aws_key'

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: velar-results.sarif
```

### Proxy Mode for Tests
```yaml
name: Test with Velar

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start Velar proxy
        uses: ubcent/velar-action@v1
        with:
          mode: 'proxy'
          fail-on-secrets: 'true'
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

      - name: Run tests
        run: npm test
        env:
          HTTP_PROXY: http://localhost:8080
          HTTPS_PROXY: http://localhost:8080

      - name: Check Velar findings
        run: velar audit summary
```

## PR Comment Example

```markdown
## Velar Security Scan Results

❌ **3 secrets detected**

### Findings

#### 📧 Email (2 occurrences)
- `src/prompts/example.txt:15` - `alice@company.com`
- `tests/fixtures/input.json:8` - `bob@example.com`

#### 🔑 API Key (1 occurrence)
- `config/dev.yaml:23` - `sk-1234567890abcdef`

### Recommendations
1. Remove hardcoded secrets from source code
2. Use environment variables or secret management
3. Add `.velar/audit.log` to `.gitignore`

---
🛡️ Powered by [Velar](https://github.com/ubcent/velar)
```

## SARIF Output

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Velar",
          "version": "0.3.0",
          "informationUri": "https://github.com/ubcent/velar"
        }
      },
      "results": [
        {
          "ruleId": "velar/email-detected",
          "level": "warning",
          "message": {
            "text": "Email address detected: alice@company.com"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/prompts/example.txt"
                },
                "region": {
                  "startLine": 15,
                  "startColumn": 20
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## Non-Goals
- Supporting other CI platforms (GitLab, Jenkins) in this task
- Secret remediation or auto-fixing
- Integration with 1Password, Vault, etc.
- Custom action configuration UI
