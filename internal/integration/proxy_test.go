package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"velar/internal/audit"
	"velar/internal/classifier"
	"velar/internal/config"
	"velar/internal/policy"
	"velar/internal/proxy"
)

type memoryAudit struct{}

func (m memoryAudit) Log(audit.Entry) error { return nil }

type proxyHarness struct {
	proxyAddr string
	shutdown  func(context.Context) error
}

func setupTestProxy(t *testing.T, cfg config.Config) *proxyHarness {
	t.Helper()
	// Keep integration tests non-interactive and deterministic.
	// Notifications are a runtime UX feature and can produce OS popups during tests.
	cfg.Notifications.Enabled = false

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen temp addr: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	pr := proxy.New(addr, policy.NewRuleEngine(cfg.Rules), classifier.HostClassifier{}, memoryAudit{}, cfg.MITM, cfg.Sanitizer, cfg.Notifications)
	errCh := make(chan error, 1)
	go func() {
		errCh <- pr.Start()
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return &proxyHarness{proxyAddr: addr, shutdown: pr.Shutdown}
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-errCh:
		t.Fatalf("proxy failed to start: %v", err)
	default:
		t.Fatalf("proxy failed to become healthy at %s", addr)
	}
	return nil
}

func (h *proxyHarness) close(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.shutdown(ctx); err != nil {
		t.Fatalf("shutdown proxy: %v", err)
	}
}

func newMockProvider(t *testing.T, onRequest func(body []byte), responseContent func(placeholder string) string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if onRequest != nil {
			onRequest(body)
		}
		placeholder := extractPlaceholder(body)
		content := "I can help with that."
		if responseContent != nil {
			content = responseContent(placeholder)
		} else if placeholder != "" {
			content = fmt.Sprintf("Sure, I'll reach out to %s right away.", placeholder)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": content}}},
		})
	}))
}

var placeholderRe = regexp.MustCompile(`\[[A-Z_]+_\d+\]`)

func extractPlaceholder(body []byte) string {
	return placeholderRe.FindString(string(body))
}

func sendThroughProxy(t *testing.T, proxyAddr, target string, payload []byte, contentType string) string {
	t.Helper()
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send request through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status=%d body=%s", resp.StatusCode, body)
	}
	return string(body)
}

func TestIntegration_MaskAndRestoreEndToEnd(t *testing.T) {
	var upstreamBody string
	provider := newMockProvider(t, func(body []byte) { upstreamBody = string(body) }, nil)
	defer provider.Close()

	cfg := config.Default()
	cfg.Sanitizer.Enabled = true
	cfg.Sanitizer.Types = []string{"email"}
	h := setupTestProxy(t, cfg)
	defer h.close(t)

	resp := sendThroughProxy(t, h.proxyAddr, provider.URL, []byte(`{"messages":[{"role":"user","content":"email me at alice@example.com"}]}`), "application/json")

	if !strings.Contains(upstreamBody, "[EMAIL_1]") || strings.Contains(upstreamBody, "alice@example.com") {
		t.Fatalf("expected upstream masked body, got: %s", upstreamBody)
	}
	if !strings.Contains(resp, "alice@example.com") || strings.Contains(resp, "[EMAIL_1]") {
		t.Fatalf("expected restored response, got: %s", resp)
	}
}

func TestIntegration_NoPIIPassthrough(t *testing.T) {
	var upstreamBody string
	provider := newMockProvider(t, func(body []byte) { upstreamBody = string(body) }, nil)
	defer provider.Close()

	cfg := config.Default()
	cfg.Sanitizer.Enabled = true
	cfg.Sanitizer.Types = []string{"email"}
	h := setupTestProxy(t, cfg)
	defer h.close(t)

	resp := sendThroughProxy(t, h.proxyAddr, provider.URL, []byte(`{"messages":[{"role":"user","content":"hello world"}]}`), "application/json")
	if !strings.Contains(upstreamBody, "hello world") {
		t.Fatalf("expected upstream to receive original body, got: %s", upstreamBody)
	}
	if !strings.Contains(resp, "I can help with that.") {
		t.Fatalf("expected normal provider response, got: %s", resp)
	}
}

func TestIntegration_MultipleEmailsInOneRequest(t *testing.T) {
	var upstreamBody string
	provider := newMockProvider(t, func(body []byte) { upstreamBody = string(body) }, func(placeholder string) string {
		return "Sure, I'll reach out to [EMAIL_1] and [EMAIL_2] right away."
	})
	defer provider.Close()

	cfg := config.Default()
	cfg.Sanitizer.Enabled = true
	cfg.Sanitizer.Types = []string{"email"}
	h := setupTestProxy(t, cfg)
	defer h.close(t)

	resp := sendThroughProxy(t, h.proxyAddr, provider.URL, []byte(`{"messages":[{"role":"user","content":"alice@example.com and bob@example.com"}]}`), "application/json")
	if !strings.Contains(upstreamBody, "[EMAIL_1]") || !strings.Contains(upstreamBody, "[EMAIL_2]") {
		t.Fatalf("expected two placeholders upstream, got: %s", upstreamBody)
	}
	if !strings.Contains(resp, "alice@example.com") || !strings.Contains(resp, "bob@example.com") {
		t.Fatalf("expected both emails restored, got: %s", resp)
	}
}

func TestIntegration_PlaceholderNotInAIResponse(t *testing.T) {
	provider := newMockProvider(t, nil, func(string) string { return "Sure, I can help with that." })
	defer provider.Close()
	cfg := config.Default()
	cfg.Sanitizer.Enabled = true
	cfg.Sanitizer.Types = []string{"email"}
	h := setupTestProxy(t, cfg)
	defer h.close(t)

	resp := sendThroughProxy(t, h.proxyAddr, provider.URL, []byte(`{"messages":[{"role":"user","content":"alice@example.com"}]}`), "application/json")
	if !strings.Contains(resp, "Sure, I can help with that.") {
		t.Fatalf("unexpected response: %s", resp)
	}
}

func TestIntegration_RestoreResponsesFalse(t *testing.T) {
	provider := newMockProvider(t, nil, nil)
	defer provider.Close()
	cfg := config.Default()
	cfg.Sanitizer.Enabled = true
	cfg.Sanitizer.Types = []string{"email"}
	cfg.Sanitizer.RestoreResponses = false
	h := setupTestProxy(t, cfg)
	defer h.close(t)

	resp := sendThroughProxy(t, h.proxyAddr, provider.URL, []byte(`{"messages":[{"role":"user","content":"alice@example.com"}]}`), "application/json")
	if !strings.Contains(resp, "[EMAIL_1]") {
		t.Fatalf("expected placeholder when restore disabled, got: %s", resp)
	}
}

func TestIntegration_LargeBodySkipped(t *testing.T) {
	var upstreamBody string
	provider := newMockProvider(t, func(body []byte) { upstreamBody = string(body) }, nil)
	defer provider.Close()
	cfg := config.Default()
	cfg.Sanitizer.Enabled = true
	cfg.Sanitizer.Types = []string{"email"}
	h := setupTestProxy(t, cfg)
	defer h.close(t)

	// large bodies are intentionally skipped
	large := strings.Repeat("x", (1<<20)+1024)
	payload := []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":"%s alice@example.com"}]}`, large))
	_ = sendThroughProxy(t, h.proxyAddr, provider.URL, payload, "application/json")

	if !strings.Contains(upstreamBody, "alice@example.com") {
		t.Fatalf("expected original email for large body, got: %s", upstreamBody)
	}
}

func TestIntegration_StreamingRequestPassthrough(t *testing.T) {
	var upstreamBody string
	provider := newMockProvider(t, func(body []byte) { upstreamBody = string(body) }, nil)
	defer provider.Close()
	cfg := config.Default()
	cfg.Sanitizer.Enabled = true
	cfg.Sanitizer.Types = []string{"email"}
	h := setupTestProxy(t, cfg)
	defer h.close(t)

	_ = sendThroughProxy(t, h.proxyAddr, provider.URL, []byte("data: alice@example.com\n\n"), "text/event-stream")
	if !strings.Contains(upstreamBody, "alice@example.com") {
		t.Fatalf("expected passthrough event-stream body, got: %s", upstreamBody)
	}
}

func TestIntegration_ConcurrentRequestsIsolation(t *testing.T) {
	t.Parallel()
	provider := newMockProvider(t, nil, nil)
	defer provider.Close()
	cfg := config.Default()
	cfg.Sanitizer.Enabled = true
	cfg.Sanitizer.Types = []string{"email"}
	h := setupTestProxy(t, cfg)
	defer h.close(t)

	const workers = 10
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			email := fmt.Sprintf("user-%d@example.com", i)
			resp := sendThroughProxy(t, h.proxyAddr, provider.URL, []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":"%s"}]}`, email)), "application/json")
			if !strings.Contains(resp, email) {
				errCh <- fmt.Errorf("response missing own email %s in %s", email, resp)
				return
			}
			for j := 0; j < workers; j++ {
				if j == i {
					continue
				}
				other := fmt.Sprintf("user-%d@example.com", j)
				if strings.Contains(resp, other) {
					errCh <- fmt.Errorf("response leaked email %s into request %s", other, email)
					return
				}
			}
			if strings.Contains(resp, "[EMAIL_") {
				errCh <- fmt.Errorf("response still has placeholder for %s: %s", email, resp)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func TestIntegration_SessionStateNotLeakedBetweenRequests(t *testing.T) {
	var received []string
	var mu sync.Mutex
	provider := newMockProvider(t, func(body []byte) {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, string(body))
	}, nil)
	defer provider.Close()
	cfg := config.Default()
	cfg.Sanitizer.Enabled = true
	cfg.Sanitizer.Types = []string{"email"}
	h := setupTestProxy(t, cfg)
	defer h.close(t)

	_ = sendThroughProxy(t, h.proxyAddr, provider.URL, []byte(`{"messages":[{"role":"user","content":"alice@example.com"}]}`), "application/json")
	resp2 := sendThroughProxy(t, h.proxyAddr, provider.URL, []byte(`{"messages":[{"role":"user","content":"hello world"}]}`), "application/json")

	mu.Lock()
	defer mu.Unlock()
	if len(received) < 2 {
		t.Fatalf("expected two upstream calls, got %d", len(received))
	}
	if strings.Contains(received[1], "[EMAIL_1]") {
		t.Fatalf("second request should not contain previous placeholder: %s", received[1])
	}
	if strings.Contains(resp2, "alice@example.com") {
		t.Fatalf("second response should not include previous session value: %s", resp2)
	}
}
