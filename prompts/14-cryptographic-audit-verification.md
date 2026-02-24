
# Task: Cryptographically Verifiable Audit Logs (Tamper-Evident)

## Objective
Implement cryptographic verification of audit logs to ensure they are tamper-evident and cryptographically verifiable. This enables detection of any unauthorized modifications to the audit trail.

## Current State
- Audit logs are written as JSONL to local files
- No integrity verification mechanism
- No protection against log tampering
- No chain-of-custody capability for compliance

## Specification

### Functional Requirements
1. **Cryptographic Signing**:
   - Sign each audit event with HMAC-SHA256 (using configurable secret key)
   - Optionally support asymmetric signing with Ed25519 (private key)
   - Include timestamp in signature calculation
   - Store signature alongside event in audit log

2. **Chain-of-Custody**:
   - Each event includes hash of previous event (merkle chain)
   - Detect if any event in middle of log is modified
   - First event signed with a genesis marker
   - Optional batch digests (e.g., every 100 events)

3. **Verification Mode**:
   - New CLI command: `velar audit verify [log_file]`
   - Validates all signatures in a log file
   - Reports chain integrity status
   - Lists any tampered events with details
   - Exit code 0 if all verified, 1 if tampering detected

4. **Seal Snapshots**:
   - Optionally create cryptographic seals at intervals
   - Seal format: aggregated hash + signature + timestamp
   - Enable comparing log integrity between time periods
   - Useful for compliance audits (prove no retroactive changes)

5. **Key Management**:
   - Symmetric key: stored in `~/.velar/audit.key` (HMAC-SHA256)
   - Optional asymmetric key pair: Ed25519 keys
   - Key rotation support with log versioning
   - Allow multiple keys for transition periods

6. **Configuration**:
   ```yaml
   audit_crypto:
     enabled: true
     algorithm: hmac-sha256  # or ed25519
     symmetric_key: ~/.velar/audit.key
     # asymmetric_private_key: ~/.velar/audit.private.key
     # asymmetric_public_key: ~/.velar/audit.public.key
     sign_events: true
     chain_of_custody: true
     batch_digest_interval: 100  # create digest every N events
     seal_snapshots: true
     seal_frequency_hours: 24
   ```

### Technical Requirements
1. Implement `internal/audit/crypto.go`:
   - `Signer` interface:
     ```go
     type Signer interface {
         Sign(event *AuditEvent, previousHash []byte) (signature []byte, eventHash []byte, error)
     }
     ```
   - `HMACSignier` implementation (HMAC-SHA256)
   - `Ed25519Signer` implementation
   - Hash chain linking function

2. Implement `internal/audit/verifier.go`:
   - `Verifier` interface:
     ```go
     type Verifier interface {
         Verify(event *AuditEvent, signature []byte, previousHash []byte) (bool, error)
         VerifyLog(filePath string) (*VerificationResult, error)
     }
     ```
   - Load events from JSONL file
   - Check all signatures sequentially
   - Detect tampering points
   - Generate detailed report

3. Implement `internal/audit/sealing.go`:
   - Create batch digests at configured intervals
   - Store seals in separate metadata file
   - Support seal verification across time periods

4. Integrate signing into audit log writing:
   - Modify `internal/audit/audit.go` to use Signer
   - Add `signature` and `previous_hash` fields to audit events
   - Ensure concurrent write safety

5. Create CLI command `internal/cmd/audit.go`:
   - `velar audit verify <log_file>` - verify log integrity
   - `velar audit seal <log_file>` - create seal snapshot
   - `velar audit rotate-key` - rotate cryptographic key
   - `velar audit export-public-key` - export Ed25519 public key

6. Key management utilities:
   - Generate HMAC keys: 32+ bytes random
   - Generate Ed25519 key pairs
   - Secure key storage with restricted permissions (0600)
   - Support reading keys from environment variables

### Acceptance Criteria
- [ ] Events are signed with HMAC-SHA256 by default
- [ ] Signature is stored in each audit event JSON
- [ ] Chain-of-custody links events with previous hash
- [ ] Log modification is detected when re-verifying
- [ ] `velar audit verify` command works correctly
- [ ] Report shows tampered events with details
- [ ] Exit code is correct (0 = verified, 1 = tampered)
- [ ] Ed25519 signing works as alternative
- [ ] Seal snapshots created at configured intervals
- [ ] Key rotation works without breaking old logs
- [ ] Performance impact < 5% on event writes
- [ ] All existing tests pass
- [ ] No plaintext keys logged or exposed

### Testing Requirements
1. Unit tests for signing/verification:
   - Test HMAC signature generation
   - Test Ed25519 signature generation
   - Test hash chain linking
   - Test signature validation
   - Add tests in `internal/audit/crypto_test.go`

2. Integration tests for log verification:
   - Write log with signatures
   - Verify complete log succeeds
   - Modify single event and verify detection
   - Modify signature and verify detection
   - Test chain breakage detection
   - Add tests in `internal/audit/verifier_test.go`

3. CLI command tests:
   - Test `velar audit verify` on valid log
   - Test `velar audit verify` on tampered log
   - Test seal creation and verification
   - Test key rotation scenarios
   - Add tests in `cmd/velar/audit_test.go`

4. Security tests:
   - Key file permissions verified (must be 0600)
   - Sensitive data not logged
   - Invalid signatures rejected
   - Timestamp tampering detected

5. Performance benchmarks:
   - Signing latency per event (target: < 1ms)
   - Verification throughput (target: > 1000 events/sec)
   - Memory usage with large logs (1M+ events)

### Files to Create/Modify
- `internal/audit/crypto.go` - NEW: signing implementations
- `internal/audit/crypto_test.go` - NEW: signing tests
- `internal/audit/verifier.go` - NEW: verification logic
- `internal/audit/verifier_test.go` - NEW: verification tests
- `internal/audit/sealing.go` - NEW: seal creation/validation
- `internal/audit/sealing_test.go` - NEW: seal tests
- `internal/audit/audit.go` - integrate signing
- `internal/audit/parser.go` - handle signature fields
- `cmd/velar/main.go` - add audit subcommand
- `cmd/velar/audit.go` - NEW: audit verify/seal/rotate CLI
- `internal/config/config.go` - add audit_crypto config section
- `docs/security.md` - document cryptographic verification
- `README.md` - document audit verification feature
- `Makefile` - add targets for key generation

### Security Considerations

1. **Key Storage**:
   - Store HMAC keys with restricted file permissions (0600)
   - Consider using system keyring for production environments
   - Support reading keys from environment variables for containers

2. **Timestamp Accuracy**:
   - Use server time for audit log timestamps
   - Account for clock skew in verification
   - Store all events with UTC timestamps

3. **Algorithm Choice**:
   - HMAC-SHA256 for symmetric scenarios (single instance/team)
   - Ed25519 for scenarios requiring public verifiability
   - No support for weak algorithms (MD5, SHA1)

4. **Compliance**:
   - Supports NIST SP 800-53 AU-10 (non-repudiation)
   - Supports SOC2 audit log integrity requirements
   - Supports GDPR audit trail requirements
   - Supports PCI-DSS log integrity controls

### Implementation Order
1. Implement basic HMAC signing in `crypto.go`
2. Implement verification in `verifier.go`
3. Integrate signing into audit log writing
4. Add CLI verify command
5. Add Ed25519 support
6. Add seal snapshots and key rotation
7. Add comprehensive tests and documentation

### Detection Examples

### Signed Audit Event
```json
{
  "timestamp": "2026-02-24T10:30:00Z",
  "event_type": "request_sanitized",
  "host": "api.openai.com",
  "sanitized_count": 3,
  "signature": "d3a7f9e2c1b5a8f3d9e2c1b5a8f3d9e2c1b5a8f3d9e2c1b5a8f3d9e2c1b5",
  "previous_hash": "c1b5a8f3d9e2c1b5a8f3d9e2c1b5a8f3d9e2c1b5a8f3d9e2c1b5a8f3d9e2",
  "event_index": 42
}
```

### Verification Report
```
Audit Log Verification Report
==============================
File: ~/.velar/audit.log
Total Events: 1000
Time Range: 2026-02-20 to 2026-02-24

✓ Signature verification: PASS (1000/1000 events)
✓ Chain-of-custody: PASS (all hashes linked)
✓ Key version consistency: PASS
✓ Timestamp ordering: PASS

Status: VERIFIED - No tampering detected

Last seal snapshot: 2026-02-24 10:00:00Z
```

### Tampered Event Detection
```
Audit Log Verification Report
==============================
File: ~/.velar/audit.log
Total Events: 1000
Time Range: 2026-02-20 to 2026-02-24

✗ Chain-of-custody: FAILED
  └─ Event #500 signature invalid
  └─ Event #501 broken link (previous_hash mismatch)
  └─ Tampering point detected at event #500

✗ 2 events with invalid signatures

Status: TAMPERED - Unauthorized modifications detected!
```

## Non-Goals
- Real-time blockchain/ledger storage (use external SIEM for that)
- Distributed ledger verification (single-node verification only)
- Client-side cryptographic verification (server-only verification)
- Key escrow services
- Hardware security module (HSM) support (future enhancement)


