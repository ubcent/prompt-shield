# Task: Audit Log Rotation

## Objective
Implement automatic log rotation for audit logs to prevent disk space exhaustion and enable efficient log management.

## Current State
- Audit logs write to a single file indefinitely (`~/.velar/audit.log`)
- No rotation mechanism exists
- Long-running instances can create very large log files
- No automatic cleanup of old logs

## Specification

### Functional Requirements
1. Automatic rotation based on:
   - **Size-based**: rotate when file reaches threshold (default: 100 MB)
   - **Time-based**: rotate daily/weekly (configurable)
   - **Combined**: whichever comes first
2. Rotation strategy:
   - Rename current log to `audit.log.1`, `audit.log.2`, etc.
   - Keep configurable number of old logs (default: 7)
   - Optionally compress old logs (gzip)
3. Rotation triggers:
   - On daemon start (check if rotation needed)
   - During write operations (size check)
   - Scheduled background check (every hour)
4. Atomic rotation:
   - No log entries lost during rotation
   - Safe for concurrent writes
5. Configuration options:
   ```yaml
   log_rotation:
     enabled: true
     max_size_mb: 100
     max_age_days: 7
     max_backups: 10
     compress: true
   ```

### Technical Requirements
1. Implement `internal/audit/rotation.go` with rotation logic:
   - `RotatingWriter` wrapping the file writer
   - Size and age checking
   - Atomic file operations
2. Use `os.Rename()` for atomic rotation
3. Background goroutine for periodic checks
4. Graceful handling of:
   - Permission errors
   - Disk full scenarios
   - Concurrent access
5. No external dependencies (pure Go stdlib)

### Acceptance Criteria
- [ ] Log rotates when size exceeds threshold
- [ ] Old logs are renamed correctly (audit.log.1, .2, etc.)
- [ ] Oldest logs are deleted when max_backups exceeded
- [ ] Compression works correctly (optional feature)
- [ ] No log entries lost during rotation
- [ ] Works correctly with concurrent writes
- [ ] Configuration options work as expected
- [ ] All existing tests pass

### Testing Requirements
1. Add unit tests for rotation logic:
   - Test size-based rotation
   - Test backup count enforcement
   - Test compression (if enabled)
2. Test concurrent writes during rotation
3. Test disk full scenario (graceful degradation)
4. Test rotation on daemon restart
5. Add tests in `internal/audit/rotation_test.go`
6. Update `internal/audit/audit_test.go` with rotation scenarios

### Files to Create/Modify
- `internal/audit/rotation.go` - NEW: rotation logic
- `internal/audit/rotation_test.go` - NEW: rotation tests
- `internal/audit/audit.go` - integrate rotating writer
- `internal/config/config.go` - add log_rotation config section
- `README.md` - document log rotation configuration

## Implementation Example

### Config Structure
```go
type LogRotation struct {
    Enabled    bool   `json:"enabled"`
    MaxSizeMB  int    `json:"max_size_mb"`
    MaxAgeDays int    `json:"max_age_days"`
    MaxBackups int    `json:"max_backups"`
    Compress   bool   `json:"compress"`
}

type Config struct {
    // ... existing fields
    LogRotation LogRotation `json:"log_rotation"`
}
```

### RotatingWriter Interface
```go
type RotatingWriter struct {
    filename    string
    file        *os.File
    size        int64
    maxSize     int64
    maxBackups  int
    maxAgeDays  int
    compress    bool
    mu          sync.Mutex
}

func NewRotatingWriter(filename string, cfg LogRotation) (*RotatingWriter, error) {
    w := &RotatingWriter{
        filename:   filename,
        maxSize:    int64(cfg.MaxSizeMB) * 1024 * 1024,
        maxBackups: cfg.MaxBackups,
        maxAgeDays: cfg.MaxAgeDays,
        compress:   cfg.Compress,
    }
    return w, w.openOrCreate()
}

func (w *RotatingWriter) Write(p []byte) (int, error) {
    w.mu.Lock()
    defer w.mu.Unlock()

    if w.shouldRotate() {
        if err := w.rotate(); err != nil {
            log.Printf("log rotation failed: %v", err)
            // Continue writing to current file
        }
    }

    n, err := w.file.Write(p)
    w.size += int64(n)
    return n, err
}

func (w *RotatingWriter) shouldRotate() bool {
    return w.maxSize > 0 && w.size >= w.maxSize
}

func (w *RotatingWriter) rotate() error {
    // Close current file
    if err := w.file.Close(); err != nil {
        return err
    }

    // Rotate existing backups: audit.log.2 -> audit.log.3, etc.
    for i := w.maxBackups - 1; i > 0; i-- {
        oldPath := fmt.Sprintf("%s.%d", w.filename, i)
        newPath := fmt.Sprintf("%s.%d", w.filename, i+1)

        if w.compress {
            oldPath += ".gz"
            newPath += ".gz"
        }

        if _, err := os.Stat(oldPath); err == nil {
            os.Rename(oldPath, newPath)
        }
    }

    // Rotate current log to .1
    backupPath := w.filename + ".1"
    if err := os.Rename(w.filename, backupPath); err != nil {
        return err
    }

    // Optionally compress
    if w.compress {
        if err := compressFile(backupPath); err != nil {
            log.Printf("compression failed: %v", err)
        }
    }

    // Clean up old backups
    w.cleanOldBackups()

    // Open new file
    return w.openOrCreate()
}

func (w *RotatingWriter) cleanOldBackups() {
    for i := w.maxBackups + 1; i < 100; i++ {
        path := fmt.Sprintf("%s.%d", w.filename, i)
        if w.compress {
            path += ".gz"
        }
        if err := os.Remove(path); err != nil {
            break
        }
    }
}
```

### Compression Helper
```go
func compressFile(src string) error {
    srcFile, err := os.Open(src)
    if err != nil {
        return err
    }
    defer srcFile.Close()

    dstFile, err := os.Create(src + ".gz")
    if err != nil {
        return err
    }
    defer dstFile.Close()

    gzWriter := gzip.NewWriter(dstFile)
    defer gzWriter.Close()

    if _, err := io.Copy(gzWriter, srcFile); err != nil {
        return err
    }

    // Remove original file after successful compression
    return os.Remove(src)
}
```

## Config Example

```yaml
log_file: ~/.velar/audit.log
log_rotation:
  enabled: true
  max_size_mb: 100        # Rotate after 100 MB
  max_age_days: 7         # Keep logs for 7 days (not implemented in basic version)
  max_backups: 10         # Keep 10 backup files
  compress: true          # Compress old logs with gzip
```

## CLI Commands (Optional Enhancement)

```bash
# View rotation status
velar logs status
# Output:
# Current log size: 45 MB
# Backups: 3 files (230 MB total)
# Next rotation: ~55 MB remaining

# Manually trigger rotation
velar logs rotate
# Output: Log rotated successfully (audit.log -> audit.log.1)

# Clean old logs
velar logs clean
# Output: Removed 5 old log files (150 MB freed)
```

## Edge Cases to Handle

1. **Disk full during rotation**:
   - Continue writing to current file
   - Log warning
   - Retry rotation on next write

2. **Permission denied**:
   - Log error
   - Continue with current file
   - Don't crash daemon

3. **Concurrent access**:
   - Use mutex for write synchronization
   - Atomic file operations (rename)

4. **Daemon restart during rotation**:
   - Check for incomplete rotation on start
   - Clean up partial files

5. **Clock skew (time-based rotation)**:
   - Use file modification time, not wall clock
   - Handle timezone changes

## Performance Considerations

- Rotation should be fast (< 10ms)
- No blocking of write operations
- Background compression (if enabled)
- Minimal memory overhead

## Non-Goals
- Centralized log aggregation (separate task)
- Log parsing or analysis
- Real-time log streaming
- Remote log shipping
- Syslog integration
- Structured logging format changes
