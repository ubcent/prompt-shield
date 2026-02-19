package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Entry struct {
	Timestamp           string           `json:"timestamp"`
	Method              string           `json:"method"`
	Host                string           `json:"host"`
	Path                string           `json:"path,omitempty"`
	Decision            string           `json:"decision"`
	Reason              string           `json:"reason"`
	RequestBodyPreview  string           `json:"request_body_preview,omitempty"`
	ResponseBodyPreview string           `json:"response_body_preview,omitempty"`
	Sanitized           bool             `json:"sanitized,omitempty"`
	SanitizedItems      []SanitizedAudit `json:"sanitized_items,omitempty"`
}

type SanitizedAudit struct {
	Type        string `json:"type"`
	Placeholder string `json:"placeholder"`
}

type Logger interface {
	Log(entry Entry) error
}

type JSONLLogger struct {
	path string
	mu   sync.Mutex
}

func NewJSONLLogger(path string) (*JSONLLogger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("create audit log: %w", err)
	}
	_ = f.Close()
	return &JSONLLogger{path: path}, nil
}

func (l *JSONLLogger) Log(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if err := enc.Encode(entry); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}
