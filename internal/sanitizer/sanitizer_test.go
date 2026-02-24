package sanitizer

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"velar/internal/session"
)

type chunkedReadCloser struct {
	chunks []string
	index  int
}

func (c *chunkedReadCloser) Read(p []byte) (int, error) {
	if c.index >= len(c.chunks) {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[c.index])
	c.index++
	return n, nil
}

func (c *chunkedReadCloser) Close() error { return nil }

func TestSanitizerReplacesValues(t *testing.T) {
	s := New([]Detector{EmailDetector{}, PhoneDetector{}})
	out, items := s.Sanitize("email john@example.com phone +123 456 7890")
	if !strings.Contains(out, "[EMAIL_1]") || !strings.Contains(out, "[PHONE_1]") {
		t.Fatalf("unexpected output: %q", out)
	}
	if len(items) != 2 {
		t.Fatalf("items=%d want 2", len(items))
	}
}

func TestSanitizerSameValueSamePlaceholder(t *testing.T) {
	s := New([]Detector{EmailDetector{}})
	out, items := s.Sanitize("john@example.com and john@example.com")
	if strings.Count(out, "[EMAIL_1]") != 2 {
		t.Fatalf("expected placeholder reused, got %q", out)
	}
	if len(items) != 1 {
		t.Fatalf("items=%d want 1", len(items))
	}
}

func TestRestore(t *testing.T) {
	orig := "send to john@example.com"
	s := New([]Detector{EmailDetector{}})
	san, items := s.Sanitize(orig)
	if Restore(san, items) != orig {
		t.Fatalf("restore mismatch: %q", Restore(san, items))
	}
}

func TestStreamingRestorerSplitPlaceholderAcrossChunks(t *testing.T) {
	restorer := NewStreamingRestorer(&chunkedReadCloser{chunks: []string{
		"Contact me at [EM",
		"AIL_1] for details",
	}}, map[string]string{
		"[EMAIL_1]": "alice@company.com",
	})
	defer restorer.Close()

	body, err := io.ReadAll(restorer)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if got := string(body); got != "Contact me at alice@company.com for details" {
		t.Fatalf("restored output mismatch: %q", got)
	}
}

func TestStreamingRestorerSplitExactlyAtBoundary(t *testing.T) {
	restorer := NewStreamingRestorer(&chunkedReadCloser{chunks: []string{"[EMAIL_", "1]"}}, map[string]string{
		"[EMAIL_1]": "alice@company.com",
	})
	defer restorer.Close()

	body, err := io.ReadAll(restorer)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if got := string(body); got != "alice@company.com" {
		t.Fatalf("exact-boundary restore mismatch: %q", got)
	}
}

func TestInspectResponseStreamingSSE(t *testing.T) {
	inspector := NewSanitizingInspector(New([]Detector{EmailDetector{}}))
	sessionID := "stream-session"
	inspector.sessions.Set(sessionID, map[string]string{"[EMAIL_1]": "alice@company.com"})

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	req = req.WithContext(session.ContextWithID(req.Context(), sessionID))

	resp := &http.Response{
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("data: contact [EMAIL_1]\n\n")),
		ContentLength: -1,
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/event-stream")
	resp.TransferEncoding = []string{"chunked"}

	out, err := inspector.InspectResponse(resp)
	if err != nil {
		t.Fatalf("InspectResponse() error = %v", err)
	}
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if strings.Contains(string(body), "[EMAIL_1]") {
		t.Fatalf("placeholder was not restored: %s", body)
	}
	if !strings.Contains(string(body), "alice@company.com") {
		t.Fatalf("restored value missing: %s", body)
	}
}

func BenchmarkStreamingRestorerChunkLatency(b *testing.B) {
	mapping := map[string]string{"[EMAIL_1]": "alice@company.com"}
	payload := "data: [EMAIL_1] says hello\n\n"
	chunk := make([]byte, 64)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		restorer := NewStreamingRestorer(io.NopCloser(bytes.NewBufferString(payload)), mapping)
		for {
			_, err := restorer.Read(chunk)
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatalf("read failed: %v", err)
			}
		}
		_ = restorer.Close()
	}
}
