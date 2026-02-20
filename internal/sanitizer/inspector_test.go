package sanitizer

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestSanitizingInspectorInspectRequestSanitizesAndRestoresBody(t *testing.T) {
	s := New([]Detector{EmailDetector{}})
	inspector := NewSanitizingInspector(s)

	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/chat/completions", strings.NewReader(`{"email":"john@example.com"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Transfer-Encoding", "chunked")

	out, err := inspector.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyText := string(body)
	if !strings.Contains(bodyText, "[EMAIL_1]") {
		t.Fatalf("expected sanitized body, got %q", bodyText)
	}
	if out.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength=%d want %d", out.ContentLength, len(body))
	}
	if got := out.Header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length header = %q, want %q", got, strconv.Itoa(len(body)))
	}
	if got := out.Header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("Transfer-Encoding header = %q, want empty", got)
	}
	if md, ok := AuditMetadataFromRequest(out); !ok || !md.Sanitized || len(md.Items) != 1 {
		t.Fatalf("expected audit metadata with one item, got ok=%v md=%+v", ok, md)
	}
}

func TestSanitizingInspectorInspectRequestSkipsNonText(t *testing.T) {
	s := New([]Detector{EmailDetector{}})
	inspector := NewSanitizingInspector(s)

	original := "not-rewritten"
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/upload", strings.NewReader(original))
	req.Header.Set("Content-Type", "application/octet-stream")

	out, err := inspector.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	body, _ := io.ReadAll(out.Body)
	if string(body) != original {
		t.Fatalf("body = %q, want %q", string(body), original)
	}
}

func TestSanitizingInspectorInspectRequestSkipsUnknownLength(t *testing.T) {
	s := New([]Detector{EmailDetector{}})
	inspector := NewSanitizingInspector(s)

	original := `{"email":"john@example.com"}`
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/stream", io.NopCloser(strings.NewReader(original)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")

	out, err := inspector.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	body, _ := io.ReadAll(out.Body)
	if string(body) != original {
		t.Fatalf("body = %q, want %q", string(body), original)
	}
}

func TestSanitizingInspectorInspectRequestSkipsEventStreamAndGet(t *testing.T) {
	s := New([]Detector{EmailDetector{}})
	inspector := NewSanitizingInspector(s)

	eventBody := "data: john@example.com\n\n"
	reqEvent, _ := http.NewRequest(http.MethodPost, "https://example.com/events", strings.NewReader(eventBody))
	reqEvent.Header.Set("Content-Type", "text/event-stream")

	outEvent, _ := inspector.InspectRequest(reqEvent)
	bodyEvent, _ := io.ReadAll(outEvent.Body)
	if string(bodyEvent) != eventBody {
		t.Fatalf("event-stream body mutated: %q", string(bodyEvent))
	}

	getBody := "john@example.com"
	reqGet, _ := http.NewRequest(http.MethodGet, "https://example.com/models", strings.NewReader(getBody))
	reqGet.Header.Set("Content-Type", "application/json")

	outGet, _ := inspector.InspectRequest(reqGet)
	bodyGet, _ := io.ReadAll(outGet.Body)
	if string(bodyGet) != getBody {
		t.Fatalf("GET body mutated: %q", string(bodyGet))
	}
}
