# Task: CLI Stats Command

## Objective
Add a CLI command to display real-time statistics and recent activity without needing a web UI.

## Current State
- No easy way to see proxy activity from CLI
- Must read log files manually to understand what's happening
- No quick status overview

## Specification

### Functional Requirements
1. `velar stats` - show current statistics:
   - Daemon status (running/stopped)
   - Uptime
   - Total requests processed (since start)
   - Total items masked by type (email, phone, api_key, etc.)
   - Requests per minute (last 5 minutes)
   - Average latencies (sanitize, upstream, total)
   - Top 5 domains
2. `velar stats --watch` - live updating stats (refresh every 2s)
3. `velar stats --recent` - show last 20 requests with details:
   - Timestamp, domain, method, status code
   - Masked items count by type
   - Latency breakdown
4. `velar stats --export json` - export stats as JSON
5. `velar stats --export csv` - export recent requests as CSV

### Technical Requirements
1. Implement `cmd/velar/stats.go` with stats command logic
2. Read statistics from:
   - In-memory stats (if daemon has stats API)
   - Parse audit log file for historical data
   - Fallback to log-only mode if daemon not running
3. Add stats API endpoint to daemon at `/api/stats` (minimal HTTP server)
   - Runs on separate port (e.g., 8081) or Unix socket
   - Returns JSON with current stats
4. Terminal output with nice formatting:
   - Use tables for structured data
   - Color coding (green=good, yellow=warning, red=error)
   - Progress bars for percentages
5. Handle case when daemon is not running gracefully

### Acceptance Criteria
- [ ] `velar stats` shows current statistics
- [ ] `velar stats --watch` updates every 2 seconds
- [ ] `velar stats --recent` shows last 20 requests
- [ ] JSON/CSV export works correctly
- [ ] Works when daemon is running
- [ ] Falls back to log parsing when daemon is stopped
- [ ] Output is readable and well-formatted
- [ ] All existing tests pass

### Testing Requirements
1. Add unit tests for stats parsing logic
2. Test with empty audit log
3. Test with large audit log (1000+ entries)
4. Test watch mode cancellation (Ctrl+C)
5. Add tests in `cmd/velar/stats_test.go`
6. Update integration tests to verify stats accuracy

### Files to Create/Modify
- `cmd/velar/stats.go` - NEW: stats command implementation
- `cmd/velar/stats_test.go` - NEW: stats tests
- `cmd/velar/main.go` - register stats command
- `internal/stats/collector.go` - NEW: stats collection logic
- `internal/stats/collector_test.go` - NEW: collector tests
- `internal/audit/parser.go` - NEW: audit log parser for stats
- `cmd/velard/main.go` - add minimal stats API endpoint
- `README.md` - document stats command

## Output Examples

### Basic Stats
```
$ velar stats

Velar Statistics
────────────────────────────────────────
Status:                 Running
Uptime:                 2h 15m 30s
Port:                   8080

Requests
────────────────────────────────────────
Total:                  1,247
Requests/min:           9.2 (last 5m)

Masked Items
────────────────────────────────────────
EMAIL:                  89  (60%)  ████████████░░░░░░░░
API_KEY:                42  (28%)  █████░░░░░░░░░░░░░░░
PHONE:                  16  (11%)  ██░░░░░░░░░░░░░░░░░░
JWT:                    2   (1%)   ░░░░░░░░░░░░░░░░░░░░
────────────────────────────────────────
Total:                  149

Latency (avg)
────────────────────────────────────────
Sanitize:               1.2ms
Upstream:               234ms
Total:                  235ms

Top Domains
────────────────────────────────────────
api.openai.com          892 requests
chatgpt.com             198 requests
api.anthropic.com       87 requests
bedrock-runtime.*.aws   45 requests
console.anthropic.com   25 requests
```

### Watch Mode
```
$ velar stats --watch

Velar Statistics (updates every 2s)              Press Ctrl+C to stop
────────────────────────────────────────
Status: Running | Uptime: 2h 15m 32s | Requests: 1,248 | Masked: 149

┌─────────────────────────────────────────────────────────────┐
│ Requests/min (last 5m)                                      │
│                                                             │
│ 15 │                                                        │
│ 10 │     ▄     ▄  ▄▄                                       │
│  5 │  ▄ ▄█▄   ██▄███▄                                      │
│  0 │▄██████████████████▄▄                                  │
│    └────────────────────────────────────────────────────── │
│      -5m        -3m        -1m         now                 │
└─────────────────────────────────────────────────────────────┘

Last request: 2s ago (api.openai.com, masked 2 EMAIL)
```

### Recent Requests
```
$ velar stats --recent

Recent Requests (last 20)
────────────────────────────────────────────────────────────────────────────
TIME       DOMAIN              METHOD  STATUS  MASKED              LATENCY
────────────────────────────────────────────────────────────────────────────
14:32:15   api.openai.com      POST    200     2 EMAIL             234ms
14:31:58   chatgpt.com         POST    200     1 PHONE             189ms
14:30:42   api.anthropic.com   POST    200     1 API_KEY           312ms
14:29:15   api.openai.com      POST    200     3 EMAIL, 1 JWT      267ms
14:28:03   api.openai.com      POST    200     -                   201ms
...
────────────────────────────────────────────────────────────────────────────
Showing 20 of 1,247 total requests
```

### JSON Export
```
$ velar stats --export json

{
  "status": "running",
  "uptime_seconds": 8130,
  "port": 8080,
  "requests": {
    "total": 1247,
    "per_minute": 9.2
  },
  "masked_items": {
    "total": 149,
    "by_type": {
      "EMAIL": 89,
      "API_KEY": 42,
      "PHONE": 16,
      "JWT": 2
    }
  },
  "latency": {
    "sanitize_ms": 1.2,
    "upstream_ms": 234,
    "total_ms": 235
  },
  "top_domains": [
    {"domain": "api.openai.com", "requests": 892},
    {"domain": "chatgpt.com", "requests": 198}
  ]
}
```

### CSV Export
```
$ velar stats --recent --export csv > requests.csv

timestamp,domain,method,status,masked_types,masked_count,latency_ms
2024-01-15T14:32:15Z,api.openai.com,POST,200,"EMAIL",2,234
2024-01-15T14:31:58Z,chatgpt.com,POST,200,"PHONE",1,189
2024-01-15T14:30:42Z,api.anthropic.com,POST,200,"API_KEY",1,312
...
```

## Implementation Notes

### Stats Collection
```go
type Stats struct {
    Status        string             `json:"status"`
    UptimeSeconds int64              `json:"uptime_seconds"`
    Port          int                `json:"port"`
    Requests      RequestStats       `json:"requests"`
    MaskedItems   MaskedItemsStats   `json:"masked_items"`
    Latency       LatencyStats       `json:"latency"`
    TopDomains    []DomainStats      `json:"top_domains"`
}

func CollectStats(auditLogPath string) (*Stats, error) {
    // Parse audit log or fetch from daemon API
}
```

### Terminal Rendering
```go
import "github.com/fatih/color"

func PrintStats(stats *Stats) {
    green := color.New(color.FgGreen).SprintFunc()
    fmt.Printf("Status: %s\n", green(stats.Status))
    // ... more formatting
}
```

## Non-Goals
- Interactive TUI (like htop) - keep it simple
- Historical graphs beyond simple ASCII charts
- Real-time streaming of requests (just periodic refresh)
- Integration with external monitoring tools (separate task)
