package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"promptshield/internal/audit"
	"promptshield/internal/classifier"
	"promptshield/internal/config"
	"promptshield/internal/policy"
	"promptshield/internal/proxy/mitm"
	"promptshield/internal/sanitizer"
)

type memoryAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (m *memoryAudit) Log(e audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}

func (m *memoryAudit) all() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]audit.Entry, len(m.entries))
	copy(out, m.entries)
	return out
}

func newTestProxy(t *testing.T, p policy.Engine, logger audit.Logger, mitmCfg config.MITM, sanitizerCfg config.Sanitizer, caDir string) (*Proxy, *httptest.Server) {
	t.Helper()
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	pr := &Proxy{transport: transport, policy: p, classifier: classifier.HostClassifier{}, audit: logger, mitmCfg: mitmCfg}
	if mitmCfg.Enabled {
		inspector := mitm.Inspector(mitm.PassthroughInspector{})
		if sanitizerCfg.Enabled {
			s := sanitizer.New(sanitizer.DetectorsByName(sanitizerCfg.Types))
			inspector = sanitizer.NewSanitizingInspector(s)
		}
		pr.mitm = mitm.NewHandler(mitm.NewCAStore(caDir), transport, p, classifier.HostClassifier{}, logger, inspector)
	}
	server := httptest.NewServer(http.HandlerFunc(pr.handle))
	return pr, server
}

func proxyClient(proxyURL string, rootCAs *x509.CertPool) *http.Client {
	proxyParsed, _ := url.Parse(proxyURL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyParsed)}
	if rootCAs != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: rootCAs}
	}
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func TestProxyAllowScenario(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	auditLog := &memoryAudit{}
	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(nil), auditLog, config.MITM{}, config.Sanitizer{}, t.TempDir())
	defer proxySrv.Close()

	client := proxyClient(proxySrv.URL, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+"/allow", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK || string(body) != "ok" || upstreamCalls.Load() != 1 || len(auditLog.all()) == 0 {
		t.Fatalf("allow flow validation failed: status=%d body=%q upstream=%d audit=%d", resp.StatusCode, body, upstreamCalls.Load(), len(auditLog.all()))
	}
}

func TestProxyBlockScenario(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rules := []config.Rule{{ID: "block-target", Match: config.Match{HostContains: "127.0.0.1"}, Action: "block"}}
	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(rules), &memoryAudit{}, config.MITM{}, config.Sanitizer{}, t.TempDir())
	defer proxySrv.Close()

	resp, err := proxyClient(proxySrv.URL, nil).Get(upstream.URL + "/blocked")
	if err != nil {
		t.Fatalf("client.Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden || upstreamCalls.Load() != 0 {
		t.Fatalf("block flow validation failed: status=%d upstream=%d", resp.StatusCode, upstreamCalls.Load())
	}
}

func TestProxyShouldMITMDecision(t *testing.T) {
	pr, _ := newTestProxy(t, policy.NewRuleEngine(nil), &memoryAudit{}, config.MITM{Enabled: true, Domains: []string{"localhost"}}, config.Sanitizer{}, t.TempDir())
	if !pr.shouldMITM("localhost:443", policy.Result{Decision: policy.MITM}) {
		t.Fatalf("expected MITM for configured domain")
	}
	if pr.shouldMITM("example.com:443", policy.Result{Decision: policy.MITM}) {
		t.Fatalf("did not expect MITM for non-configured domain")
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "api.openai.com:443", want: "api.openai.com"},
		{input: "api.openai.com", want: "api.openai.com"},
		{input: "[::1]:8443", want: "::1"},
	}
	for _, tc := range tests {
		if got := normalizeHost(tc.input); got != tc.want {
			t.Fatalf("normalizeHost(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestProxyConnectReturnsEstablishedInsteadOfRedirect(t *testing.T) {
	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(nil), &memoryAudit{}, config.MITM{}, config.Sanitizer{}, t.TempDir())
	defer proxySrv.Close()

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	proxyAddr := strings.TrimPrefix(proxySrv.URL, "http://")
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("CONNECT " + upstream.Addr().String() + " HTTP/1.1\r\nHost: " + upstream.Addr().String() + "\r\n\r\n")); err != nil {
		t.Fatalf("write connect request: %v", err)
	}

	statusLine, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected CONNECT 200, got %q", strings.TrimSpace(statusLine))
	}
}

func TestProxyAuditLoggingJSON(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("audit"))
	}))
	defer upstream.Close()

	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.NewJSONLLogger(logPath)
	if err != nil {
		t.Fatalf("NewJSONLLogger() error = %v", err)
	}
	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(nil), logger, config.MITM{}, config.Sanitizer{}, t.TempDir())
	defer proxySrv.Close()

	resp, err := proxyClient(proxySrv.URL, nil).Get(upstream.URL + "/audit")
	if err != nil {
		t.Fatalf("client.Get() error = %v", err)
	}
	resp.Body.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var entry audit.Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("audit log is not valid json: %v", err)
	}
	if entry.Decision != string(policy.Allow) || entry.Method != http.MethodGet {
		t.Fatalf("unexpected audit entry: %+v", entry)
	}
}
