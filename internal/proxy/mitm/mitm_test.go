package mitm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"promptshield/internal/classifier"
	"promptshield/internal/policy"
	"promptshield/internal/sanitizer"
)

type noopAudit struct{}

func (noopAudit) Log(_ interface{}) error { return nil }

type rewriteInspector struct{}

func (rewriteInspector) InspectRequest(r *http.Request) (*http.Request, error) {
	payload := []byte(`{"rewritten":true}`)
	r.Body = io.NopCloser(bytes.NewReader(payload))
	r.ContentLength = int64(len(payload))
	r.Header.Set("Content-Length", "18")
	return r, nil
}

func (rewriteInspector) InspectResponse(r *http.Response) (*http.Response, error) {
	return r, nil
}

type countingInspector struct {
	requestCalls  int
	responseCalls int
}

func (i *countingInspector) InspectRequest(r *http.Request) (*http.Request, error) {
	i.requestCalls++
	return r, nil
}

func (i *countingInspector) InspectResponse(r *http.Response) (*http.Response, error) {
	i.responseCalls++
	return r, nil
}

func TestCAStoreRootAndLeafCertificate(t *testing.T) {
	dir := t.TempDir()
	store := NewCAStore(dir)
	if err := store.EnsureRootCA(); err != nil {
		t.Fatalf("EnsureRootCA() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "cert.pem")); err != nil {
		t.Fatalf("expected cert.pem to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "key.pem")); err != nil {
		t.Fatalf("expected key.pem to exist: %v", err)
	}

	leaf, err := store.GetLeafCert("api.openai.com")
	if err != nil {
		t.Fatalf("GetLeafCert() error = %v", err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if cert.Subject.CommonName != "api.openai.com" {
		t.Fatalf("leaf CN = %q, want %q", cert.Subject.CommonName, "api.openai.com")
	}

	again, err := store.GetLeafCert("api.openai.com")
	if err != nil {
		t.Fatalf("GetLeafCert() second call error = %v", err)
	}
	if leaf != again {
		t.Fatalf("expected cached certificate pointer to be reused")
	}
}

func TestInspectorCanRewriteRequestBody(t *testing.T) {
	var (
		gotBody []byte
		mu      sync.Mutex
	)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	store := NewCAStore(t.TempDir())
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	h := NewHandler(
		store,
		transport,
		policy.NewRuleEngine(nil),
		classifier.HostClassifier{},
		nil,
		rewriteInspector{},
	)

	req := httptest.NewRequest(http.MethodPost, "https://proxy/", bytes.NewBufferString(`{"original":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.serverHandler(upstream.Listener.Addr().String()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	mu.Lock()
	defer mu.Unlock()
	if string(gotBody) != `{"rewritten":true}` {
		t.Fatalf("upstream body = %q, want rewritten payload", gotBody)
	}
}

func TestSanitizerInspectorRewritesSensitiveData(t *testing.T) {
	var gotBody []byte
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	s := sanitizer.New([]sanitizer.Detector{sanitizer.EmailDetector{}, sanitizer.PhoneDetector{}})
	h := NewHandler(
		NewCAStore(t.TempDir()),
		&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		policy.NewRuleEngine(nil),
		classifier.HostClassifier{},
		nil,
		sanitizer.NewSanitizingInspector(s),
	)

	req := httptest.NewRequest(http.MethodPost, "https://proxy/", bytes.NewBufferString(`{"prompt":"contact john@example.com or +123 456 7890"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.serverHandler(upstream.Listener.Addr().String()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := string(gotBody)
	if !strings.Contains(body, "[EMAIL_1]") || !strings.Contains(body, "[PHONE_1]") {
		t.Fatalf("expected sanitized body, got %q", body)
	}
}

func TestSanitizerRestoresResponseBody(t *testing.T) {
	// This test verifies the full round-trip:
	// 1. Client sends request with sensitive data
	// 2. Request is sanitized before going upstream (email -> [EMAIL_1])
	// 3. Upstream echoes the request body in response
	// 4. Response body is restored (placeholders -> original values)
	// 5. Client receives the restored response with original values

	var (
		gotRequestBody []byte
		mu             sync.Mutex
	)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotRequestBody = body
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		// Echo the request back in the response
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	s := sanitizer.New([]sanitizer.Detector{sanitizer.EmailDetector{}})
	inspector := sanitizer.NewSanitizingInspector(s)

	h := NewHandler(
		NewCAStore(t.TempDir()),
		&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		policy.NewRuleEngine(nil),
		classifier.HostClassifier{},
		nil,
		inspector,
	)

	// Wire the handler's sessions store to the inspector so restore works
	inspector.WithSessions(h.sessions)

	originalEmail := "dvbondarchuk@gmail.com"
	originalBody := `{"email":"` + originalEmail + `"}`

	req := httptest.NewRequest(http.MethodPost, "https://proxy/", bytes.NewBufferString(originalBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.serverHandler(upstream.Listener.Addr().String()).ServeHTTP(rec, req)

	// Verify upstream received sanitized request
	mu.Lock()
	upstreamBody := string(gotRequestBody)
	mu.Unlock()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if !strings.Contains(upstreamBody, "[EMAIL_1]") {
		t.Fatalf("upstream should receive sanitized body with [EMAIL_1], got %q", upstreamBody)
	}

	if strings.Contains(upstreamBody, originalEmail) {
		t.Fatalf("upstream should NOT receive original email, but got %q", upstreamBody)
	}

	// Verify client received restored response
	clientBody := rec.Body.String()

	if !strings.Contains(clientBody, originalEmail) {
		t.Fatalf("client response should contain original email %q, got %q", originalEmail, clientBody)
	}

	if strings.Contains(clientBody, "[EMAIL_1]") {
		t.Fatalf("client response should NOT contain placeholder [EMAIL_1], got %q", clientBody)
	}

	t.Logf("✓ Request sanitization: %s -> [EMAIL_1]", originalEmail)
	t.Logf("✓ Response restoration: [EMAIL_1] -> %s", originalEmail)
}

func TestStreamingResponseSkipsInspectionAndRestore(t *testing.T) {
	inspector := &countingInspector{}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: hello\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write([]byte("data: world\n\n"))
	}))
	defer upstream.Close()

	h := NewHandler(
		NewCAStore(t.TempDir()),
		&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		policy.NewRuleEngine(nil),
		classifier.HostClassifier{},
		nil,
		inspector,
	)

	req := httptest.NewRequest(http.MethodGet, "https://proxy/", nil)
	rec := httptest.NewRecorder()

	h.serverHandler(upstream.Listener.Addr().String()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if inspector.requestCalls != 1 {
		t.Fatalf("InspectRequest calls = %d, want 1", inspector.requestCalls)
	}
	if inspector.responseCalls != 0 {
		t.Fatalf("InspectResponse calls = %d, want 0 for event-stream", inspector.responseCalls)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(strings.ToLower(got), "text/event-stream") {
		t.Fatalf("content-type = %q, want text/event-stream", got)
	}
	if got := rec.Body.String(); got != "data: hello\n\ndata: world\n\n" {
		t.Fatalf("stream body mismatch: %q", got)
	}
}
