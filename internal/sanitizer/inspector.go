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
	"promptshield/internal/session"
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
	sessions             *session.Store
}

func NewSanitizingInspector(s *Sanitizer) *SanitizingInspector {
	return &SanitizingInspector{sanitizer: s, maxBodySize: defaultMaxBodyBytes, sessions: session.NewStore()}
}

func (i *SanitizingInspector) WithNotifications(enabled bool) *SanitizingInspector {
	i.notificationsEnabled = enabled
	return i
}

func (i *SanitizingInspector) WithSessions(store *session.Store) *SanitizingInspector {
	if store != nil {
		i.sessions = store
	}
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
		strings.Contains(ct, "application/x-www-form-urlencoded") ||
		strings.Contains(ct, "text/")
}

type sessionIDContextKeyType struct{}

var sessionIDContextKey = sessionIDContextKeyType{}

func (i *SanitizingInspector) InspectRequest(r *http.Request) (*http.Request, error) {
	log.Printf("sanitizer: inspect request: %s %s (ContentLength=%d)", r.Method, r.URL, r.ContentLength)
	if r == nil || i == nil || i.sanitizer == nil {
		log.Printf("sanitizer: skipping - missing prerequisites")
		return r, nil
	}

	// Try to get sessionID from context (set by MITM handler), or generate a new one
	sessionID := session.GetIDFromContext(r.Context())
	if sessionID == "" {
		sessionID = session.GenerateID()
		if sessionID != "" {
			r = r.WithContext(session.ContextWithID(r.Context(), sessionID))
		}
	}
	log.Printf("sanitizer: using sessionID=%s", sessionID)

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
	if r.ContentLength > limit || r.ContentLength < 0 {
		log.Printf("sanitizer: skipping - unsupported body size (%d)", r.ContentLength)
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
		mapping := make(map[string]string, len(items))
		for _, item := range items {
			mapping[item.Placeholder] = item.Original
		}
		i.sessions.Set(sessionID, mapping)
		if i.notificationsEnabled {
			msg := fmt.Sprintf(
				"Detected: %s\nMasked before sending and restored locally",
				strings.Join(uniqueTypes(items), ", "),
			)
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
	if r == nil || i == nil || i.sessions == nil {
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
	if r.ContentLength > limit || r.ContentLength < 0 {
		return r, nil
	}
	if r.Request == nil {
		return r, nil
	}
	sessionID := session.GetIDFromContext(r.Request.Context())
	if sessionID == "" {
		return r, nil
	}
	// Note: Do not delete the session here - let the MITM handler manage the lifecycle
	// to ensure the mapping is available for response restoration
	sess, ok := i.sessions.Get(sessionID)
	if !ok || len(sess.Mapping) == 0 || r.Body == nil {
		return r, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return r, nil
	}
	_ = r.Body.Close()
	if int64(len(body)) > limit {
		return r, nil
	}
	restored := string(body)
	for placeholder, original := range sess.Mapping {
		restored = strings.ReplaceAll(restored, placeholder, original)
	}
	newBody := []byte(restored)
	r.Body = io.NopCloser(bytes.NewReader(newBody))
	r.ContentLength = int64(len(newBody))
	r.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	r.Header.Del("Transfer-Encoding")
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
