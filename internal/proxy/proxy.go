package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"promptshield/internal/audit"
	"promptshield/internal/classifier"
	"promptshield/internal/policy"
)

type Server interface {
	Start() error
	Shutdown(ctx context.Context) error
}

type Proxy struct {
	httpServer *http.Server
	transport  *http.Transport
	policy     policy.Engine
	classifier classifier.Classifier
	audit      audit.Logger
}

func New(addr string, p policy.Engine, c classifier.Classifier, a audit.Logger) *Proxy {
	pr := &Proxy{
		transport:  &http.Transport{Proxy: http.ProxyFromEnvironment},
		policy:     p,
		classifier: c,
		audit:      a,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", pr.handle)
	pr.httpServer = &http.Server{Addr: addr, Handler: mux}
	return pr
}

func (p *Proxy) Start() error {
	log.Printf("promptshield daemon listening on %s", p.httpServer.Addr)
	err := p.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	return p.httpServer.Shutdown(ctx)
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	if host == "" && r.URL != nil {
		host = hostOnly(r.URL.Host)
	}

	_ = p.classifier.Classify(host)
	decision := p.policy.Evaluate(host)

	entry := audit.Entry{
		Method:   r.Method,
		Host:     host,
		Path:     r.URL.Path,
		Decision: string(decision.Decision),
		Reason:   fmt.Sprintf("%s (%s)", decision.Reason, decision.RuleID),
	}
	defer func() {
		if err := p.audit.Log(entry); err != nil {
			log.Printf("audit log error: %v", err)
		}
	}()

	if decision.Decision == policy.Block {
		http.Error(w, "blocked by PromptShield policy", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = r.Host
	}

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	dstConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		dstConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		dstConn.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var wg sync.WaitGroup
	wg.Add(2)
	go tunnel(&wg, dstConn, clientConn)
	go tunnel(&wg, clientConn, dstConn)
	wg.Wait()
}

func tunnel(wg *sync.WaitGroup, dst net.Conn, src net.Conn) {
	defer wg.Done()
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func copyHeader(dst, src http.Header) {
	for k, values := range src {
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

func hostOnly(hostport string) string {
	if hostport == "" {
		return ""
	}
	if strings.Contains(hostport, ":") {
		h, _, err := net.SplitHostPort(hostport)
		if err == nil {
			return h
		}
	}
	return hostport
}
