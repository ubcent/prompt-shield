package sanitizer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"promptshield/internal/notifier"
)

const defaultMaxBodyBytes int64 = 1 << 20

var errBodyTooLarge = errors.New("body too large")

type auditContextKey struct{}

type AuditMetadata struct {
	Sanitized bool
	Items     []SanitizedItem
}

type SanitizingInspector struct {
	sanitizer            *Sanitizer
	maxBodySize          int64
	notificationsEnabled bool
}

func NewSanitizingInspector(s *Sanitizer) *SanitizingInspector {
	return &SanitizingInspector{sanitizer: s, maxBodySize: defaultMaxBodyBytes}
}

func (i *SanitizingInspector) WithNotifications(enabled bool) *SanitizingInspector {
	i.notificationsEnabled = enabled
	return i
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
	log.Printf("sanitizer: inspect request: %s %s (ContentLength=%d)", r.Method, r.URL, r.ContentLength)
	if r == nil || i == nil || i.sanitizer == nil {
		log.Printf("sanitizer: skipping - missing prerequisites")
		return r, nil
	}
	if r.Method == http.MethodGet || r.Body == nil {
		log.Printf("sanitizer: skipping - GET or no body")
		return r, nil
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "text/event-stream") {
		log.Printf("sanitizer: skipping - event-stream")
		return r, nil
	}
	if !isTextContent(r.Header.Get("Content-Type")) {
		log.Printf("sanitizer: skipping - not text content (type=%s)", r.Header.Get("Content-Type"))
		return r, nil
	}
	limit := i.maxBodySize
	if limit <= 0 {
		limit = defaultMaxBodyBytes
	}
	if r.ContentLength > limit {
		log.Printf("sanitizer: skipping - body too large (%d > %d)", r.ContentLength, limit)
		return r, nil
	}

	body, err := readBodySafe(r, limit)
	if err != nil {
		log.Printf("sanitizer: read error: %v", err)
		return r, nil
	}
	if len(body) == 0 {
		log.Printf("sanitizer: empty body")
		restoreBody(r, body)
		return r, nil
	}

	log.Printf("sanitizer: scanning body (%d bytes)", len(body))
	sanitized, items := i.sanitizer.Sanitize(string(body))
	newBody := []byte(sanitized)
	restoreBody(r, newBody)
	if len(items) > 0 {
		log.Printf("sanitizer: found %d sensitive items: %v", len(items), uniqueTypes(items))
		if i.notificationsEnabled {
			msg := fmt.Sprintf("Sensitive data detected: %s", strings.Join(uniqueTypes(items), ", "))
			log.Printf("sanitizer: sending notification: %s", msg)
			notifier.Notify("PromptShield", msg)
		}
		r = withAuditMetadata(r, AuditMetadata{Sanitized: true, Items: items})
	} else {
		log.Printf("sanitizer: no sensitive data found")
	}
	return r, nil
}

func uniqueTypes(items []SanitizedItem) []string {
	seen := make(map[string]struct{}, len(items))
	types := make([]string, 0, len(items))
	for _, item := range items {
		typ := strings.TrimSpace(item.Type)
		if typ == "" {
			continue
		}
		if _, ok := seen[typ]; ok {
			continue
		}
		seen[typ] = struct{}{}
		types = append(types, typ)
	}
	return types
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
