package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"promptshield/internal/audit"
	"promptshield/internal/classifier"
	"promptshield/internal/policy"
	"promptshield/internal/sanitizer"
)

const (
	maxBodySize      = 1 << 20
	maxAuditBodySize = 512
)

type Handler struct {
	ca         *CAStore
	transport  *http.Transport
	inspector  Inspector
	policy     policy.Engine
	classifier classifier.Classifier
	audit      audit.Logger
}

func NewHandler(ca *CAStore, transport *http.Transport, p policy.Engine, cls classifier.Classifier, logger audit.Logger, insp Inspector) *Handler {
	if insp == nil {
		insp = PassthroughInspector{}
	}
	return &Handler{ca: ca, transport: transport, policy: p, classifier: cls, audit: logger, inspector: insp}
}

func (h *Handler) HandleMITM(clientConn net.Conn, host string) {
	defer clientConn.Close()

	cert, err := h.ca.GetLeafCert(hostOnly(host))
	if err != nil {
		log.Printf("mitm cert error for %s: %v", host, err)
		return
	}
	tlsClient := tls.Server(clientConn, &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err := tlsClient.Handshake(); err != nil {
		log.Printf("mitm client handshake failed for %s: %v", host, err)
		return
	}
	defer tlsClient.Close()

	srv := &http.Server{Handler: h.serverHandler(host), ReadHeaderTimeout: 10 * time.Second}
	_ = srv.Serve(&singleConnListener{conn: tlsClient})
	_ = srv.Shutdown(context.Background())
}

func (h *Handler) serverHandler(connectHost string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := hostOnly(connectHost)
		_ = h.classifier.Classify(host)
		decision := h.policy.Evaluate(host)
		if decision.Decision == policy.Block {
			http.Error(w, "blocked by PromptShield policy", http.StatusForbidden)
			h.logAudit(r, host, decision, "", "")
			return
		}

		req, reqPreview, err := cloneLimitedRequest(r, maxBodySize)
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = connectHost
		req.RequestURI = ""
		req.Host = connectHost

		req, err = h.inspector.InspectRequest(req)
		if err != nil {
			http.Error(w, "request inspection failed", http.StatusBadRequest)
			return
		}
		if updatedPreview, ok := requestJSONPreview(req); ok {
			reqPreview = updatedPreview
		}

		resp, err := h.transport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		resp, respPreview, err := cloneLimitedResponse(resp, maxBodySize)
		if err != nil {
			http.Error(w, "upstream body too large", http.StatusBadGateway)
			return
		}
		resp, err = h.inspector.InspectResponse(resp)
		if err != nil {
			http.Error(w, "response inspection failed", http.StatusBadGateway)
			return
		}

		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		h.logAudit(req, host, decision, reqPreview, respPreview)
	})
}

func (h *Handler) logAudit(r *http.Request, host string, decision policy.Result, reqPreview, respPreview string) {
	if h.audit == nil {
		return
	}
	entry := audit.Entry{Method: r.Method, Host: host, Path: r.URL.Path, Decision: string(decision.Decision), Reason: fmt.Sprintf("%s (%s)", decision.Reason, decision.RuleID), RequestBodyPreview: reqPreview, ResponseBodyPreview: respPreview}
	if md, ok := sanitizer.AuditMetadataFromRequest(r); ok && md.Sanitized {
		entry.Sanitized = true
		entry.SanitizedItems = make([]audit.SanitizedAudit, 0, len(md.Items))
		for _, item := range md.Items {
			entry.SanitizedItems = append(entry.SanitizedItems, audit.SanitizedAudit{Type: item.Type, Placeholder: item.Placeholder})
		}
	}
	_ = h.audit.Log(entry)
}

func requestJSONPreview(r *http.Request) (string, bool) {
	if r.Body == nil {
		return "", false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return "", false
	}
	preview := string(body)
	if len(preview) > maxAuditBodySize {
		preview = preview[:maxAuditBodySize]
	}
	preview = strings.ReplaceAll(preview, "\n", "")
	return preview, true
}

func cloneLimitedRequest(r *http.Request, limit int64) (*http.Request, string, error) {
	out := r.Clone(r.Context())
	if r.Body == nil {
		return out, "", nil
	}
	body, preview, err := readLimitedBody(r.Body, r.Header.Get("Content-Type"), limit)
	if err != nil {
		return nil, "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	return out, preview, nil
}

func cloneLimitedResponse(r *http.Response, limit int64) (*http.Response, string, error) {
	if r.Body == nil {
		return r, "", nil
	}
	body, preview, err := readLimitedBody(r.Body, r.Header.Get("Content-Type"), limit)
	if err != nil {
		return nil, "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return r, preview, nil
}

func readLimitedBody(rc io.ReadCloser, contentType string, limit int64) ([]byte, string, error) {
	defer rc.Close()
	body, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > limit {
		return nil, "", fmt.Errorf("body exceeds limit")
	}
	if !strings.Contains(strings.ToLower(contentType), "application/json") {
		return body, "", nil
	}
	preview := string(body)
	if len(preview) > maxAuditBodySize {
		preview = preview[:maxAuditBodySize]
	}
	preview = strings.ReplaceAll(preview, "\n", "")
	return body, preview, nil
}

type singleConnListener struct{ conn net.Conn }

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, io.EOF
	}
	c := l.conn
	l.conn = nil
	return c, nil
}
func (l *singleConnListener) Close() error { return nil }
func (l *singleConnListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err == nil {
		return host
	}
	return hostport
}

func copyHeader(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func HandleMITM(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "standalone MITM handler is not wired", http.StatusNotImplemented)
}
