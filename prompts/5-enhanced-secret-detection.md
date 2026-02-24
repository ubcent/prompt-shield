# Task: Enhanced Secret Detection

## Objective
Expand secret detection beyond basic API keys to cover AWS credentials, private keys, database URLs, and other common secrets.

## Current State
- Basic detection exists for generic `api_key` patterns
- No specific AWS/GCP/Azure key detection
- No private key or certificate detection
- No database connection string detection

## Specification

### Functional Requirements
1. Detect AWS credentials:
   - AWS Access Key ID: `AKIA[A-Z0-9]{16}`
   - AWS Secret Access Key: `[A-Za-z0-9/+=]{40}`
   - AWS Session Token patterns
2. Detect GCP credentials:
   - Service account keys (JSON format detection)
   - API keys with GCP prefix patterns
3. Detect Azure credentials:
   - Connection strings with `AccountKey=`
   - SAS tokens
4. Detect private keys:
   - RSA/DSA/EC private key BEGIN/END blocks
   - SSH private key patterns
5. Detect database URLs:
   - PostgreSQL: `postgresql://user:pass@host:port/db`
   - MySQL: `mysql://user:pass@host:port/db`
   - MongoDB: `mongodb://user:pass@host:port/db`
   - Redis: `redis://user:pass@host:port`
6. Detect JWT tokens (already exists, ensure it's comprehensive)
7. Detect generic secrets:
   - High-entropy strings (Shannon entropy > threshold)
   - Hex-encoded secrets (32+ chars)

### Technical Requirements
1. Implement new detectors in `internal/detect/secret_detectors.go`
2. Each secret type gets dedicated regex + validation logic
3. Add entropy calculation for high-entropy string detection
4. Ensure low false positive rate (< 5% in tests)
5. Support confidence scoring per detection
6. Add secret-specific placeholder types (e.g., `[AWS_KEY_1]`, `[DB_URL_1]`)

### Acceptance Criteria
- [ ] Detects all AWS credential formats from AWS SDK examples
- [ ] Detects GCP service account JSON keys
- [ ] Detects RSA/EC private keys in PEM format
- [ ] Detects common database connection strings
- [ ] False positive rate < 5% on sample code corpus
- [ ] All existing PII detection tests pass
- [ ] Performance impact < 10% on average request

### Testing Requirements
1. Create test corpus with 50+ real secret patterns
2. Add unit tests for each detector type
3. Test false positives with code snippets (variable names, comments)
4. Benchmark detector performance
5. Add tests in `internal/detect/secret_detectors_test.go`
6. Update `internal/sanitizer/sanitizer_test.go` with secret scenarios

### Files to Create/Modify
- `internal/detect/secret_detectors.go` - NEW: secret-specific detectors
- `internal/detect/secret_detectors_test.go` - NEW: secret detector tests
- `internal/detect/entropy.go` - NEW: entropy calculation utilities
- `internal/sanitizer/factory.go` - register new secret detectors
- `internal/config/config.go` - add secret types to default config
- `README.md` - document new secret types

## Detection Examples

### AWS Access Key
```
Pattern: AKIA[A-Z0-9]{16}
Example: AKIAIOSFODNN7EXAMPLE
Placeholder: [AWS_ACCESS_KEY_1]
```

### Private Key
```
Pattern: -----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----
Example: -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...
Placeholder: [PRIVATE_KEY_1]
```

### Database URL
```
Pattern: (postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+
Example: postgresql://user:secret123@db.example.com:5432/mydb
Placeholder: [DB_URL_1]
```

### High-Entropy String
```
Criteria: Shannon entropy > 4.5, length >= 32, alphanumeric
Example: 7d8a9f2b1c3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9
Placeholder: [HIGH_ENTROPY_1]
```

## Non-Goals
- Real-time secret validation (checking if keys are valid/active)
- Secrets database for known leaked credentials
- Custom secret patterns via config (future feature)
- Binary file scanning
