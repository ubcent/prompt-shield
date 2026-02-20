package sanitizer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

const defaultMaxBodyBytes int64 = 1 << 20

var errBodyTooLarge = errors.New("body too large")

type auditContextKey struct{}

type AuditMetadata struct {
	Sanitized bool
	Items     []SanitizedItem
}

type SanitizingInspector struct {
	sanitizer   *Sanitizer
	maxBodySize int64
}

func NewSanitizingInspector(s *Sanitizer) *SanitizingInspector {
	return &SanitizingInspector{sanitizer: s, maxBodySize: defaultMaxBodyBytes}
}

func readBodySafe(r *http.Request, maxSize int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSize+1))
	if err != nil {
		_ = r.Body.Close()
		return nil, err
	}
	_ = r.Body.Close()
	if int64(len(body)) > maxSize {
		return nil, errBodyTooLarge
	}
	return body, nil
}

func restoreBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	r.Header.Del("Transfer-Encoding")
}

func isTextContent(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "text/plain") ||
		strings.Contains(ct, "application/x-www-form-urlencoded")
}

func (i *SanitizingInspector) InspectRequest(r *http.Request) (*http.Request, error) {
	log.Printf("inspect request: %s %s", r.Method, r.URL)
	if r == nil || i == nil || i.sanitizer == nil {
		return r, nil
	}
	if r.Method == http.MethodGet || r.Body == nil {
		return r, nil
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "text/event-stream") {
		return r, nil
	}
	if !isTextContent(r.Header.Get("Content-Type")) {
		return r, nil
	}
	limit := i.maxBodySize
	if limit <= 0 {
		limit = defaultMaxBodyBytes
	}
	if r.ContentLength < 0 || r.ContentLength > limit {
		return r, nil
	}

	body, err := readBodySafe(r, limit)
	if err != nil {
		log.Printf("sanitizer read error: %v", err)
		return r, nil
	}
	if len(body) == 0 {
		restoreBody(r, body)
		return r, nil
	}

	sanitized, items := i.sanitizer.Sanitize(string(body))
	newBody := []byte(sanitized)
	restoreBody(r, newBody)
	if len(items) > 0 {
		log.Printf("sanitized %d items", len(items))
		r = withAuditMetadata(r, AuditMetadata{Sanitized: true, Items: items})
	}
	return r, nil
}

func (i *SanitizingInspector) InspectResponse(r *http.Response) (*http.Response, error) {
	return r, nil
}

func withAuditMetadata(r *http.Request, md AuditMetadata) *http.Request {
	ctx := context.WithValue(r.Context(), auditContextKey{}, md)
	return r.WithContext(ctx)
}

func AuditMetadataFromRequest(r *http.Request) (AuditMetadata, bool) {
	v := r.Context().Value(auditContextKey{})
	md, ok := v.(AuditMetadata)
	return md, ok
}
