# Task: Vector Firewall - Tenant-Aware RAG Authorization & Poisoning Defense

## Objective
Implement a "vector firewall" that intercepts similarity search queries and results to enforce tenant-aware authorization, detect poisoned vectors (persistent prompt injection), and prevent cross-tenant data leakage in RAG (Retrieval-Augmented Generation) systems.

## Current State
- Velar protects outbound LLM requests and inbound tool access (MCP)
- No protection for the vector/embedding layer
- RAG systems retrieve context from vector databases (Pinecone, Weaviate, Chroma, Milvus, etc.)
- No tenant isolation enforcement at retrieval time
- Poisoned vectors can execute persistent prompt injection attacks
- Cross-tenant leakage risks in multi-tenant RAG deployments
- Vector store operations logged but not validated for access control

## Problem Context

### The New Attack Surface (RAG Layer)
```
Traditional Pipeline:
  User Input → LLM → Output ✓ (covered by Velar)

RAG Pipeline (NEW VULNERABILITY):
  User Input → [Vector DB Query] → Retrieval → LLM → Output
                      ↑ (NOT PROTECTED)
             Data leakage risk, poisoning risk
```

### Documented Risks
1. **Cross-Tenant Leakage** (OWASP RAG Controls):
   - Query vectors are NOT tenant-filtered → retrieves neighbor vectors
   - Similarity search doesn't respect access boundaries
   - Example: Customer A's query retrieves Customer B's documents
   - Cloud vendor guidance (AWS Bedrock, Azure AI Search) explicitly warns

2. **Persistent Prompt Injection via Poisoned Vectors**:
   - Attacker injects malicious document into vector store
   - Document is embedded and indexed
   - Similarity search retrieves it as "relevant context"
   - Injected instructions execute in LLM (even with isolated prompts)
   - Unlike direct prompt injection, persistent across all users

3. **Vector Poisoning Scenarios**:
   - Attacker uploads file: "SYSTEM OVERRIDE: Ignore previous instructions..."
   - Document gets embedded and indexed
   - User later queries unrelated topic
   - Poisoned document retrieved due to embedding ambiguity
   - Instruction injection persists for weeks/months if undetected

### Why This Matters NOW (2026)
- **RAG Adoption**: 80%+ of enterprise LLM deployments use RAG
- **Multi-Tenant SaaS**: RAG as a service (Pinecone, Weaviate Cloud)
- **Cloud Provider Focus**: AWS/Azure/GCP publish RAG security guides
- **Research**: Demonstrated persistent injection, embedding poisoning, model extraction via RAG
- **Compliance**: SOC2, HIPAA now explicitly mention vector isolation requirements

## Specification

### Functional Requirements

#### 1. Tenant-Aware Vector Query Authorization
1. **Query Interception**:
   - Intercept similarity search requests (before hitting vector DB)
   - Identify tenant/user context from query metadata/JWT/session
   - Validate access to vector collections
   
2. **Tenant Filtering**:
   - Enforce automatic `tenant_id` filter in all queries
   - Prevent queries without explicit tenant context
   - Support hierarchical tenants (org → team → user)
   - Handle guest/anonymous queries safely (deny by default)

3. **Access Control Models**:
   - **Namespace isolation**: Each tenant has separate namespace
   - **Metadata filtering**: All vectors tagged with `tenant_id`
   - **Collection-level ACL**: Different collections per tenant
   - **Row-level security**: Filter vectors by user/tenant metadata
   - **Cross-tenant search**: Explicit opt-in with audit logging

#### 2. Vector Poisoning Detection
1. **Content-Based Detection**:
   - Scan document embeddings before indexing
   - Detect instruction-like patterns (e.g., "SYSTEM:", "IGNORE:", "OVERRIDE:")
   - Check for prompt injection keywords in embedded text
   - Flag suspicious semantic patterns (e.g., high attention to control tokens)

2. **Behavioral Detection**:
   - Monitor retrieval patterns: unusual neighbors for query
   - Detect: document retrieved despite low similarity score
   - Detect: document appears in results for unrelated queries
   - Statistical anomaly detection: outlier embeddings

3. **Signature-Based Detection**:
   - Known poisoning patterns (regex-based)
   - Obfuscated injections (base64, Unicode, reverse text in embeddings)
   - PII/secret injection attempts via vectors
   - Cross-reference with prompt injection patterns (Task #15)

4. **Post-Retrieval Filtering**:
   - Quarantine suspected poisoned vectors
   - Flag in audit trail with confidence score
   - Optional: auto-remove if high confidence + approval
   - Admin dashboard: review suspected vectors

#### 3. Retrieval Result Validation
1. **Integrity Checks**:
   - Verify metadata consistency: does `tenant_id` match query?
   - Check document source: is it from authorized collection?
   - Validate embedding: is it legitimately similar?
   
2. **Sanitization**:
   - Remove or redact sensitive metadata from results
   - Extract only necessary fields (text, relevance score)
   - Strip internal IDs, source paths (if not needed by LLM)

3. **Rate Limiting & Anomaly**:
   - Per-tenant rate limits on vector queries
   - Detect: suspicious query patterns (embedding extraction attacks)
   - Detect: bulk vector retrieval (model theft via embeddings)

#### 4. Configuration Model
```yaml
vector_firewall:
  enabled: true
  
  # Tenant isolation
  tenant_mode: required  # required | optional | disabled
  tenant_context_sources:
    - jwt_claim: "org_id"
    - header: "X-Tenant-ID"
    - session_variable: "tenant_id"
  
  # Authorization
  vector_db_providers:
    pinecone:
      enabled: true
      namespace_per_tenant: true
      metadata_filter_field: "tenant_id"
    
    weaviate:
      enabled: true
      collection_per_tenant: true
      
    chroma:
      enabled: true
      collection_per_tenant: true
  
  # Poisoning detection
  poisoning_detection:
    enabled: true
    
    content_scanning:
      enabled: true
      patterns:
        - "system\\s*(override|instruction):"
        - "ignore\\s*previous"
        - "bypass\\s*filter"
      obfuscation_detection: true
    
    behavioral_anomaly:
      enabled: true
      similarity_threshold: 0.5  # flag if below
      statistical_zscore: 3.0    # flag if outlier
      learning_period_days: 30
    
    action_on_detection:
      action: quarantine  # quarantine | block | flag | log
      require_approval: true
      notify_admin: true
  
  # Retrieval filtering
  retrieval_filtering:
    enabled: true
    max_results_per_query: 10
    redact_metadata: true
    sanitize_fields:
      - internal_id
      - source_path
      - embedding_vector
  
  # Rate limiting
  rate_limiting:
    enabled: true
    queries_per_minute: 100
    vectors_per_query: 20
    extract_vectors_per_hour: 10  # detect embedding theft

# Audit configuration (uses Task #14 signing)
audit:
  log_vector_queries: true
  log_poisoned_detections: true
  log_tenant_violations: true
  sign_events: true
```

#### 5. Integration Points
1. **Vector DB Proxying**:
   - Act as proxy between client and vector DB
   - Support: Pinecone, Weaviate, Chroma, Milvus, pgvector, Qdrant
   - Transparent to application (same API)

2. **LLM Context Injection**:
   - Pass retrieval metadata to Task #15 (toxic flow detection)
   - Flag if injected content looks suspicious
   - Include source/tenant info in LLM context

3. **Audit Integration** (Task #14):
   - Log all vector queries with tenant info
   - Sign detection events with cryptographic signatures
   - SIEM export (Task #8) for suspicious retrievals

### Technical Requirements

#### 1. Core Components

1. **`internal/vector/firewall.go`**:
   ```go
   type VectorFirewall interface {
       // Query interception
       InterceptQuery(ctx context.Context, query *VectorQuery) (*AuthorizedQuery, error)
       
       // Tenant validation
       ValidateTenantAccess(tenantID, collectionID string) (bool, error)
       
       // Result filtering
       FilterResults(ctx context.Context, results []Vector, tenantID string) ([]Vector, error)
   }
   ```

2. **`internal/vector/tenant_filter.go`**:
   - Extract tenant context from request (JWT, header, session)
   - Validate tenant has access to collections
   - Attach tenant filter to queries
   - Support hierarchical tenants

3. **`internal/vector/poisoning_detector.go`**:
   ```go
   type PoisoningDetector interface {
       // Content scanning
       ScanDocument(ctx context.Context, doc *Document) (*PoisoningResult, error)
       
       // Behavioral detection
       DetectAnomalies(ctx context.Context, retrieval *Retrieval) (*AnomalyScore, error)
       
       // Pattern matching
       MatchPatterns(text string) ([]*PatternMatch, error)
   }
   ```

4. **`internal/vector/vector_db_proxy.go`**:
   - Pinecone client wrapper
   - Weaviate client wrapper
   - Chroma client wrapper
   - Milvus client wrapper
   - Transparent query modification + result filtering

5. **`internal/vector/embedding_validator.go`**:
   - Validate embedding before indexing
   - Quarantine suspicious embeddings
   - Flag outliers for manual review

6. **`internal/vector/audit.go`**:
   - Log vector queries with full context
   - Integration with Task #14 (cryptographic signing)
   - Anomaly event logging

#### 2. Proxy Architecture

```
┌────────────────────────────────┐
│ Application (RAG + LLM)         │
├────────────────────────────────┤
│                                 │
│ query = client.search(          │
│   query="what is X?",           │
│   top_k=5                       │
│ )                               │
└────────────┬────────────────────┘
             │
             ↓ HTTP/gRPC
┌────────────────────────────────┐
│ VELAR VECTOR FIREWALL           │
├────────────────────────────────┤
│ 1. Extract tenant from context  │
│ 2. Validate access              │
│ 3. Add tenant filter to query   │
│ 4. Send to vector DB            │
└────────────┬────────────────────┘
             │
             ↓
┌────────────────────────────────┐
│ Vector Database                 │
│ (Pinecone/Weaviate/Chroma)     │
└────────────┬────────────────────┘
             │
             ↓ results
┌────────────────────────────────┐
│ VELAR VECTOR FIREWALL           │
├────────────────────────────────┤
│ 1. Check poisoning (each vector)│
│ 2. Verify tenant metadata       │
│ 3. Redact sensitive fields      │
│ 4. Log retrieval               │
│ 5. Return sanitized results    │
└────────────┬────────────────────┘
             │
             ↓
┌────────────────────────────────┐
│ Application (RAG + LLM)         │
│ Receives: [Vector, Vector, ...] │
│ (tenant-filtered, validated)    │
└────────────────────────────────┘
```

#### 3. Vector DB Adapters

1. **`internal/vector/adapters/pinecone.go`**:
   - Intercept queries
   - Auto-add metadata filter for tenant
   - Parse and filter results

2. **`internal/vector/adapters/weaviate.go`**:
   - GraphQL query modification
   - Collection-level filtering
   - Result metadata validation

3. **`internal/vector/adapters/chroma.go`**:
   - Collection isolation per tenant
   - Metadata filter injection
   - Distance threshold validation

4. **`internal/vector/adapters/pgvector.go`**:
   - SQL query modification
   - Row-level security filtering
   - Audit logging

#### 4. CLI Commands

1. **`velar vector`** subcommand:
   ```bash
   velar vector firewall status
   velar vector firewall test [--tenant=org-1]
   velar vector tenants list
   velar vector tenants add [name]
   velar vector poisoning detect [log-file]
   velar vector poisoning quarantine [vector-id]
   velar vector poisoning review
   velar vector stats [--tenant=org-1]
   ```

2. **`velar audit vector`** (extension of Task #15):
   ```bash
   velar audit vector-queries [--tenant=org-1] [--timerange=24h]
   velar audit vector-anomalies [--severity=high]
   velar audit cross-tenant-attempts
   ```

#### 5. HTTP API

```
# Query interception
POST   /api/v1/vector/query           (proxy to vector DB)
POST   /api/v1/vector/query-batch     (batch queries)

# Tenant management
GET    /api/v1/vector/tenants
POST   /api/v1/vector/tenants
GET    /api/v1/vector/tenants/{id}
PUT    /api/v1/vector/tenants/{id}

# Poisoning management
GET    /api/v1/vector/poisoning/quarantine
POST   /api/v1/vector/poisoning/quarantine/{id}/approve
POST   /api/v1/vector/poisoning/quarantine/{id}/reject

# Audit
GET    /api/v1/vector/audit?tenant=...&type=...
GET    /api/v1/vector/stats?tenant=...
```

### Acceptance Criteria
- [ ] Vector queries automatically filtered by tenant
- [ ] Cross-tenant queries blocked (unless explicitly allowed + audited)
- [ ] Poisoned vectors detected with >85% accuracy (known patterns)
- [ ] Obfuscated poisoning patterns detected (base64, Unicode, reverse)
- [ ] Anomalous retrievals flagged for review
- [ ] All vector queries logged with tenant + source
- [ ] Cryptographic signatures on all audit events (Task #14)
- [ ] Rate limiting enforced per tenant
- [ ] Results sanitized (sensitive metadata redacted)
- [ ] Pinecone adapter working
- [ ] Weaviate adapter working
- [ ] Chroma adapter working
- [ ] CLI commands functional
- [ ] HTTP API accessible
- [ ] Performance overhead < 20ms per query
- [ ] No false negatives on known poisoning patterns
- [ ] All existing tests pass

### Testing Requirements

1. **Tenant Isolation Tests** (`internal/vector/firewall_test.go`):
   - Cross-tenant query blocked
   - Tenant filter applied correctly
   - Hierarchical tenant support
   - Guest/anonymous query handling

2. **Poisoning Detection Tests** (`internal/vector/poisoning_test.go`):
   - Known injection patterns detected
   - Obfuscated patterns detected (base64, Unicode)
   - Behavioral anomalies detected
   - False positive rate < 10%

3. **Vector DB Adapter Tests** (`internal/vector/adapters/*_test.go`):
   - Pinecone query modification
   - Weaviate collection filtering
   - Chroma isolation
   - Result filtering

4. **Audit Logging Tests**:
   - Vector queries logged
   - Poisoning detections logged with signature
   - Tenant violations logged
   - SIEM export works

5. **End-to-End Tests**:
   - App queries → Firewall → Vector DB → Results
   - Poisoned vector blocks/quarantines
   - Cross-tenant attempt blocked

6. **Security Tests**:
   - Embedding extraction attacks blocked (rate limit)
   - Model theft via vector search prevented
   - Tenant bypass attempts detected

7. **Performance Benchmarks**:
   - Query latency: < 20ms overhead
   - Poisoning detection: < 10ms per vector
   - Throughput: > 1000 queries/sec

### Files to Create/Modify
- `internal/vector/firewall.go` - NEW: core firewall logic
- `internal/vector/tenant_filter.go` - NEW: tenant context extraction
- `internal/vector/poisoning_detector.go` - NEW: poisoning detection
- `internal/vector/embedding_validator.go` - NEW: pre-indexing validation
- `internal/vector/vector_db_proxy.go` - NEW: proxy pattern implementation
- `internal/vector/audit.go` - NEW: audit logging
- `internal/vector/firewall_test.go` - NEW: firewall tests
- `internal/vector/poisoning_test.go` - NEW: poisoning detection tests
- `internal/vector/adapters/pinecone.go` - NEW: Pinecone adapter
- `internal/vector/adapters/weaviate.go` - NEW: Weaviate adapter
- `internal/vector/adapters/chroma.go` - NEW: Chroma adapter
- `internal/vector/adapters/pgvector.go` - NEW: pgvector adapter
- `internal/vector/adapters/adapter_test.go` - NEW: adapter tests
- `cmd/velar/main.go` - integrate vector subcommand
- `cmd/velar/vector.go` - NEW: vector CLI
- `internal/config/config.go` - add vector_firewall config
- `docs/vector-security.md` - NEW: vector security guide
- `docs/RAG-SECURITY-PATTERNS.md` - NEW: RAG best practices
- `README.md` - document vector firewall feature

### Security Considerations

1. **Tenant Isolation Guarantees**:
   - All queries MUST include tenant context (fail-closed)
   - No query execution without tenant validation
   - Audit trail proves tenant separation
   - Regular testing of cross-tenant leak scenarios

2. **Poisoning Detection Layers**:
   - Layer 1: Content scanning before indexing
   - Layer 2: Behavioral anomalies post-indexing
   - Layer 3: Signature matching on retrieval
   - Layer 4: LLM-aware validation (Task #15 integration)

3. **Embedding Privacy**:
   - Do NOT log raw embeddings
   - Do NOT cache embedding vectors in logs
   - Log only metadata, hash, poison scores
   - Sensitive embeddings should be encrypted at rest

4. **Compliance Mapping**:
   - **HIPAA**: Tenant isolation (required for patient data)
   - **SOC2**: Audit trail + access control
   - **GDPR**: Right to erasure (vectors should be deletable)
   - **PCI-DSS**: Cardholder data isolation
   - **NIST SP 800-53 AC-3**: Access Control
   - **OWASP RAG Controls**: Vector isolation explicit

5. **Defense Against**:
   - Cross-tenant data leakage (direct mitigation)
   - Persistent prompt injection (detection + quarantine)
   - Embedding space poisoning (anomaly detection)
   - Model extraction via similarity search (rate limit)
   - Tenant bypass (fail-closed validation)

### Implementation Order
1. Define tenant filtering and authorization model
2. Implement vector DB proxying (start with Pinecone)
3. Implement poisoning detection (regex patterns first)
4. Add behavioral anomaly detection
5. Add other vector DB adapters
6. Implement audit logging (integrate Task #14)
7. Add CLI commands
8. Add HTTP API
9. Comprehensive testing
10. Documentation

### Related Features
- **Feature #14 (Cryptographic Audit)**: Sign all vector events
- **Feature #15 (Toxic Flow Detection)**: Validate retrieved context
- **Feature #8 (SIEM Export)**: Export vector anomalies
- **Feature #7 (Team Policies)**: Define tenant policies

### Examples

#### Example 1: Multi-Tenant RAG Query
```json
// Application request
{
  "query": "what are our security policies?",
  "top_k": 5,
  "tenant_id": "org-acme"  // from JWT or header
}

// Velar firewall processes:
{
  "original_query": "what are our security policies?",
  "embedding": [0.1, 0.2, ...],  // computed
  "tenant_filter": { "tenant_id": "org-acme" },
  "collection": "acme_documents",
  "modified_query": "what are our security policies?",
  "metadata_filter": "tenant_id = 'org-acme'"
}

// Vector DB returns neighbors matching org-acme only

// Velar filters results:
{
  "results": [
    {
      "id": "vec_123",
      "text": "Policy: ...",
      "score": 0.95,
      "tenant_id": "org-acme",
      "poisoning_score": 0.0  // not poisoned
    },
    ...
  ]
}
```

#### Example 2: Poisoning Detection
```json
{
  "detection_type": "poisoned_vector",
  "vector_id": "vec_456",
  "tenant_id": "org-acme",
  "detection_method": "content_pattern",
  "pattern_matched": "system override:",
  "confidence": 0.98,
  "action_taken": "quarantine",
  "detected_at": "2026-02-24T14:30:00Z",
  "snippet": "...SYSTEM OVERRIDE: Ignore previous instructions...",
  "source_document": "uploaded_file_2026_02_24.pdf",
  "signature": "d3a7f9e2c1b5a8f3d9e2c1b5a8f3d9e2c1b5a8f..."
}
```

#### Example 3: Cross-Tenant Attack Attempt
```json
{
  "event_type": "cross_tenant_attempt",
  "severity": "critical",
  "query": "embedding: [0.1, 0.2, ...]",
  "requesting_tenant": "org-acme",
  "attempted_target_collection": "org-evil_documents",
  "action_taken": "blocked",
  "reason": "tenant_mismatch",
  "timestamp": "2026-02-24T14:31:00Z",
  "user_ip": "192.168.1.100",
  "signature": "c1b5a8f3d9e2c1b5a8f3d9e2c1b5a8f3d9e2..."
}
```

#### Example 4: Rate Limit on Embedding Extraction
```json
{
  "event_type": "rate_limit_exceeded",
  "tenant_id": "org-acme",
  "limit_type": "vectors_extracted_per_hour",
  "threshold": 10,
  "actual": 150,
  "action_taken": "block",
  "detected_pattern": "systematic_embedding_extraction",
  "risk_assessment": "possible_model_theft_attempt",
  "timestamp": "2026-02-24T14:32:00Z"
}
```

## Non-Goals
- Cloud-native deployment (single-machine focus, like other Velar features)
- Real-time retraining of anomaly models (use static baselines)
- Homomorphic encryption on embeddings (compute local only)
- Distributed vector DB synchronization
- Automatic vector deletion (only quarantine + flagging)

## Questions to Consider Before Implementation
1. Should poisoned vectors be auto-deleted after approval, or just quarantined forever?
2. How aggressive should anomaly detection be? (false positive cost vs security)
3. Should we support federated vector DB access (multiple vector DBs per tenant)?
4. Should embedding extraction be completely blocked, or rate-limited?
5. How often to retrain behavioral baselines? (weekly, monthly?)
6. Should vector queries be logged with full text, or hashed for privacy?


