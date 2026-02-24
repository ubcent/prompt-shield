# Task: Audit Log Export to SIEM

## Objective
Enable exporting Velar audit logs to SIEM systems (Splunk, Elasticsearch, Datadog) for centralized security monitoring.

## Current State
- Audit logs are local JSONL files
- No integration with external logging systems
- Hard to aggregate logs across multiple machines

## Specification

### Functional Requirements
1. Export audit logs to:
   - Splunk HTTP Event Collector (HEC)
   - Elasticsearch bulk API
   - Datadog logs API
   - Generic HTTP endpoint (JSON POST)
   - Syslog (RFC 5424)
2. Buffered batching:
   - Batch up to 100 events or 10 seconds (configurable)
   - Retry on failure with exponential backoff
   - Drop oldest events if buffer full (with warning)
3. Filtering:
   - Only export events with `sanitized_count > 0`
   - Only export events matching specific domains
   - Exclude internal/health check requests
4. Enrichment:
   - Add hostname, machine ID, Velar version to each event
   - Add custom tags from config
5. Async operation:
   - Non-blocking audit log writes
   - Graceful shutdown with buffer flush

### Technical Requirements
1. Implement `internal/export/exporter.go` interface:
   ```go
   type Exporter interface {
       Export(ctx context.Context, events []AuditEvent) error
       Close() error
   }
   ```
2. Implement specific exporters:
   - `internal/export/splunk.go` - Splunk HEC
   - `internal/export/elasticsearch.go` - Elasticsearch
   - `internal/export/datadog.go` - Datadog
   - `internal/export/http.go` - Generic HTTP
   - `internal/export/syslog.go` - Syslog
3. Add `internal/export/buffer.go` for batching logic
4. Add retry logic with exponential backoff
5. Support multiple exporters simultaneously

### Acceptance Criteria
- [ ] Events export to Splunk HEC successfully
- [ ] Events export to Elasticsearch bulk API successfully
- [ ] Batching works correctly (waits for batch size or timeout)
- [ ] Retry on failure with exponential backoff
- [ ] Graceful shutdown flushes buffer
- [ ] No memory leaks during long-running operation
- [ ] Performance impact < 5% on proxy latency
- [ ] All existing tests pass

### Testing Requirements
1. Mock SIEM endpoints for testing
2. Test batching logic with various event rates
3. Test retry logic with simulated failures
4. Test graceful shutdown and buffer flush
5. Add tests in `internal/export/exporter_test.go`
6. Add integration test with real Elasticsearch instance (Docker)

### Files to Create/Modify
- `internal/export/exporter.go` - NEW: exporter interface
- `internal/export/splunk.go` - NEW: Splunk exporter
- `internal/export/elasticsearch.go` - NEW: Elasticsearch exporter
- `internal/export/datadog.go` - NEW: Datadog exporter
- `internal/export/http.go` - NEW: generic HTTP exporter
- `internal/export/syslog.go` - NEW: syslog exporter
- `internal/export/buffer.go` - NEW: batching logic
- `internal/export/exporter_test.go` - NEW: exporter tests
- `internal/config/config.go` - add export config section
- `internal/audit/audit.go` - integrate exporter
- `README.md` - document SIEM integration

## Config Example

```yaml
export:
  enabled: true
  exporters:
    - type: splunk
      url: "https://splunk.company.com:8088/services/collector"
      token: "YOUR-HEC-TOKEN"
      index: "velar-audit"
      source_type: "velar:audit"
      batch_size: 100
      batch_timeout: 10s
      retry_max_attempts: 3
      retry_initial_delay: 1s

    - type: elasticsearch
      url: "https://elasticsearch.company.com:9200"
      index: "velar-audit"
      username: "velar"
      password: "secret"
      batch_size: 50
      batch_timeout: 5s

    - type: datadog
      api_key: "YOUR-DD-API-KEY"
      site: "datadoghq.com"
      service: "velar"
      tags:
        - "env:production"
        - "team:security"

  filters:
    min_sanitized_count: 1
    domains:
      - "api.openai.com"
      - "api.anthropic.com"
    exclude_paths:
      - "/health"
      - "/metrics"
```

## Splunk HEC Example

### Request Format
```json
POST https://splunk.company.com:8088/services/collector
Authorization: Splunk YOUR-HEC-TOKEN

{
  "time": 1705315200,
  "source": "velar",
  "sourcetype": "velar:audit",
  "index": "velar-audit",
  "event": {
    "request_id": "req_123",
    "timestamp": "2024-01-15T14:30:00Z",
    "host": "api.openai.com",
    "path": "/v1/chat/completions",
    "method": "POST",
    "status_code": 200,
    "sanitized_count": 2,
    "sanitized_types": ["email", "phone"],
    "latency_ms": 450,
    "velar_version": "v0.3.0",
    "hostname": "dev-machine-1"
  }
}
```

## Elasticsearch Example

### Request Format
```json
POST https://elasticsearch.company.com:9200/_bulk
Content-Type: application/x-ndjson

{"index":{"_index":"velar-audit","_id":"req_123"}}
{"request_id":"req_123","timestamp":"2024-01-15T14:30:00Z","host":"api.openai.com",...}
{"index":{"_index":"velar-audit","_id":"req_124"}}
{"request_id":"req_124","timestamp":"2024-01-15T14:30:05Z","host":"chatgpt.com",...}
```

## Non-Goals
- Real-time streaming (batching is acceptable)
- Log compression or encryption in transit (use HTTPS)
- Schema transformation or complex ETL
- Support for every SIEM vendor
