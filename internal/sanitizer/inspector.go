package sanitizer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const defaultMaxBodyBytes int64 = 1 << 20

type auditContextKey struct{}

type AuditMetadata struct {
	Sanitized bool
	Items     []SanitizedItem
}

type SanitizingInspector struct {
	sanitizer    *Sanitizer
	maxBodyBytes int64
}

func NewSanitizingInspector(s *Sanitizer) *SanitizingInspector {
	return &SanitizingInspector{sanitizer: s, maxBodyBytes: defaultMaxBodyBytes}
}

func (i *SanitizingInspector) InspectRequest(r *http.Request) (*http.Request, error) {
	if i == nil || i.sanitizer == nil || !supportedContentType(r.Header.Get("Content-Type")) || r.Body == nil {
		return r, nil
	}
	limit := i.maxBodyBytes
	if limit <= 0 {
		limit = defaultMaxBodyBytes
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	_ = r.Body.Close()
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("body too large")
	}

	sanitizedText, items := i.sanitizer.Sanitize(string(body))
	sanitizedBytes := []byte(sanitizedText)
	r.Body = io.NopCloser(bytes.NewReader(sanitizedBytes))
	r.ContentLength = int64(len(sanitizedBytes))
	r.Header.Set("Content-Length", fmt.Sprintf("%d", len(sanitizedBytes)))
	if len(items) > 0 {
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

func supportedContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "text/plain")
}
