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
	"promptshield/internal/config"
	"promptshield/internal/policy"
	"promptshield/internal/proxy/mitm"
	"promptshield/internal/sanitizer"
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
	mitm       *mitm.Handler
	mitmCfg    config.MITM
}

func New(addr string, p policy.Engine, c classifier.Classifier, a audit.Logger, mitmCfg config.MITM, sanitizerCfg config.Sanitizer) *Proxy {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	pr := &Proxy{
		transport:  transport,
		policy:     p,
		classifier: c,
		audit:      a,
		mitmCfg:    mitmCfg,
	}
	if mitmCfg.Enabled {
		baseDir, err := mitm.DefaultCAPath()
		if err != nil {
			log.Printf("mitm disabled: cannot resolve CA path: %v", err)
		} else {
			inspector := mitm.Inspector(mitm.PassthroughInspector{})
			if sanitizerCfg.Enabled {
				detectors := sanitizer.DetectorsByName(sanitizerCfg.Types)
				s := sanitizer.New(detectors).WithConfidenceThreshold(sanitizerCfg.ConfidenceThreshold).WithMaxReplacements(sanitizerCfg.MaxReplacements)
				inspector = sanitizer.NewSanitizingInspector(s)
			}
			pr.mitm = mitm.NewHandler(mitm.NewCAStore(baseDir), transport, p, c, a, inspector)
		}
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

	entry := audit.Entry{Method: r.Method, Host: host, Path: r.URL.Path, Decision: string(decision.Decision), Reason: fmt.Sprintf("%s (%s)", decision.Reason, decision.RuleID)}
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
		p.handleConnect(w, r, decision)
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

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request, decision policy.Result) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if p.shouldMITM(r.Host, decision) {
		p.mitm.HandleMITM(clientConn, r.Host)
		return
	}

	dstConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		_ = clientConn.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go tunnel(&wg, dstConn, clientConn)
	go tunnel(&wg, clientConn, dstConn)
	wg.Wait()
}

func (p *Proxy) shouldMITM(host string, decision policy.Result) bool {
	if p.mitm == nil || !p.mitmCfg.Enabled {
		return false
	}
	if decision.Decision != policy.MITM {
		return false
	}
	if len(p.mitmCfg.Domains) == 0 {
		return true
	}
	needle := strings.ToLower(hostOnly(host))
	for _, domain := range p.mitmCfg.Domains {
		if strings.EqualFold(strings.TrimSpace(domain), needle) {
			return true
		}
	}
	return false
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
