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
