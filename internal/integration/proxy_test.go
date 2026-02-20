package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if strings.TrimSpace(os.Getenv("RUN_INTEGRATION")) == "" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestMaskAndRestore(t *testing.T) {
	responseBody := sendThroughProxy(t, map[string]string{"message": "email me at alice@example.com"})
	if !strings.Contains(responseBody, "alice@example.com") {
		t.Fatalf("client response should contain original email, got: %s", responseBody)
	}
	if strings.Contains(responseBody, "[EMAIL_1]") {
		t.Fatalf("client response should not contain placeholder, got: %s", responseBody)
	}

	upstreamBody := fetchUpstreamLastBody(t)
	if !strings.Contains(upstreamBody, "[EMAIL_1]") {
		t.Fatalf("upstream request should be masked, got: %s", upstreamBody)
	}
	if strings.Contains(upstreamBody, "alice@example.com") {
		t.Fatalf("upstream request should not contain original email, got: %s", upstreamBody)
	}
}

func TestNoPIIPassthrough(t *testing.T) {
	responseBody := sendThroughProxy(t, map[string]string{"message": "hello world"})
	if !strings.Contains(responseBody, "hello world") {
		t.Fatalf("expected unchanged response body, got: %s", responseBody)
	}
	upstreamBody := fetchUpstreamLastBody(t)
	if !strings.Contains(upstreamBody, "hello world") {
		t.Fatalf("expected unchanged upstream body, got: %s", upstreamBody)
	}
}

func TestMultiplePII(t *testing.T) {
	responseBody := sendThroughProxy(t, map[string]string{"message": "alice@example.com and bob@example.com"})
	if !strings.Contains(responseBody, "alice@example.com") || !strings.Contains(responseBody, "bob@example.com") {
		t.Fatalf("response should restore both emails, got: %s", responseBody)
	}
	if strings.Contains(responseBody, "[EMAIL_1]") || strings.Contains(responseBody, "[EMAIL_2]") {
		t.Fatalf("response should not contain placeholders, got: %s", responseBody)
	}

	upstreamBody := fetchUpstreamLastBody(t)
	if !strings.Contains(upstreamBody, "[EMAIL_1]") || !strings.Contains(upstreamBody, "[EMAIL_2]") {
		t.Fatalf("upstream should contain placeholders for both emails, got: %s", upstreamBody)
	}
}

func TestLargeBodySkipped(t *testing.T) {
	large := strings.Repeat("x", (1<<20)+1024)
	original := "large payload " + large + " tail@example.com"
	responseBody := sendThroughProxy(t, map[string]string{"message": original})

	if !strings.Contains(responseBody, "tail@example.com") {
		t.Fatalf("expected original email when sanitization is skipped, got: %s", responseBody)
	}

	upstreamBody := fetchUpstreamLastBody(t)
	if !strings.Contains(upstreamBody, "tail@example.com") {
		t.Fatalf("upstream should receive original email for large body, got: %s", upstreamBody)
	}
}

func TestConcurrentRequestsIsolation(t *testing.T) {
	const workers = 10
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			email := fmt.Sprintf("user-%d@example.com", i)
			responseBody := sendThroughProxy(t, map[string]string{"message": email})
			if !strings.Contains(responseBody, email) {
				errCh <- fmt.Errorf("response missing original email %q: %s", email, responseBody)
				return
			}
			if strings.Contains(responseBody, "[EMAIL_") {
				errCh <- fmt.Errorf("response still contains placeholder for %q: %s", email, responseBody)
				return
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func sendThroughProxy(t *testing.T, payload map[string]string) string {
	t.Helper()

	proxyURL, err := url.Parse("http://" + envOrDefault("INTEGRATION_PROXY_ADDR", "localhost:8080"))
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	target := "http://" + envOrDefault("INTEGRATION_ECHO_ADDR", "localhost:9000") + "/"
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send request through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response status %d body=%s", resp.StatusCode, string(body))
	}
	return string(body)
}

func fetchUpstreamLastBody(t *testing.T) string {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}
	endpoint := "http://" + envOrDefault("INTEGRATION_ECHO_ADDR", "localhost:9000") + "/last"
	resp, err := client.Get(endpoint)
	if err != nil {
		t.Fatalf("get upstream /last: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read upstream /last body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected /last status %d body=%s", resp.StatusCode, string(body))
	}

	var parsed map[string]string
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal /last body: %v (body=%s)", err, string(body))
	}
	return parsed["received"]
}

func envOrDefault(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
