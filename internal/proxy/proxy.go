package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
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

func New(addr string, p policy.Engine, c classifier.Classifier, a audit.Logger, mitmCfg config.MITM, sanitizerCfg config.Sanitizer, notificationCfg config.Notifications) *Proxy {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}
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
				log.Printf("proxy: initializing SanitizingInspector (notificationsEnabled=%v)", notificationCfg.Enabled)
				detectors := sanitizer.DetectorsByName(sanitizerCfg.Types)
				s := sanitizer.New(detectors).WithConfidenceThreshold(sanitizerCfg.ConfidenceThreshold).WithMaxReplacements(sanitizerCfg.MaxReplacements)
				inspector = sanitizer.NewSanitizingInspector(s).WithNotifications(notificationCfg.Enabled)
			}
			pr.mitm = mitm.NewHandler(mitm.NewCAStore(baseDir), transport, p, c, a, inspector)
		}
	}
	pr.httpServer = &http.Server{Addr: addr, Handler: http.HandlerFunc(pr.handle)}
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
	host := normalizeHost(r.Host)
	if host == "" && r.URL != nil {
		host = normalizeHost(r.URL.Host)
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
	target := connectTarget(r.Host)
	if target == "" {
		http.Error(w, "missing CONNECT target", http.StatusBadRequest)
		return
	}

	host := normalizeHost(target)
	decision := p.policy.Evaluate(host)
	log.Printf("CONNECT %s decision=%s", target, decision.Decision)

	if p.shouldMITM(target, decision) {
		log.Printf("CONNECT request to %s (mode=mitm)", target)
		p.handleMITM(w, r, target)
		return
	}
	log.Printf("CONNECT request to %s (mode=tunnel)", target)
	p.handleTunnel(w, target)
}

func (p *Proxy) handleMITM(w http.ResponseWriter, r *http.Request, target string) {
	log.Printf("handleMITM: starting for %s", target)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("handleMITM: hijack failed for %s: %v", target, err)
		return
	}

	log.Printf("handleMITM: sending 200 Connection Established to %s", target)
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	log.Printf("handleMITM: delegating to MITM handler for %s", target)
	p.mitm.HandleMITM(clientConn, target)
	log.Printf("handleMITM: completed for %s", target)
}

func (p *Proxy) handleTunnel(w http.ResponseWriter, target string) {
	dstConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		http.Error(w, "failed to connect upstream", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = dstConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		_ = dstConn.Close()
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		_ = dstConn.Close()
		return
	}

	go tunnel(dstConn, clientConn)
	tunnel(clientConn, dstConn)
}

func connectTarget(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if strings.Contains(host, ":") {
		return host
	}
	return net.JoinHostPort(host, "443")
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
	needle := strings.ToLower(normalizeHost(host))
	for _, domain := range p.mitmCfg.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if needle == domain || strings.HasSuffix(needle, "."+domain) {
			return true
		}
	}
	return false
}

func tunnel(dst net.Conn, src net.Conn) {
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

func normalizeHost(hostport string) string {
	if hostport == "" {
		return ""
	}
	if strings.HasPrefix(hostport, "[") {
		h, _, err := net.SplitHostPort(hostport)
		if err == nil {
			return h
		}
	}
	if strings.Contains(hostport, ":") {
		h, _, err := net.SplitHostPort(hostport)
		if err == nil {
			return h
		}
		parts := strings.Split(hostport, ":")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return hostport
}
