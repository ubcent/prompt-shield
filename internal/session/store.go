package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
)

type Session struct {
	ID      string
	Mapping map[string]string
}

type Store struct {
	sync.Map
}

// contextKeyType is used as the context key for storing session IDs
type contextKeyType struct{}

// ContextKey is the key for storing/retrieving session IDs from request context
var ContextKey = contextKeyType{}

func NewStore() *Store {
	return &Store{}
}

func GenerateID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

func (s *Store) Set(sessionID string, mapping map[string]string) {
	if s == nil || sessionID == "" {
		return
	}
	copied := make(map[string]string, len(mapping))
	for placeholder, original := range mapping {
		copied[placeholder] = original
	}
	s.Store(sessionID, Session{ID: sessionID, Mapping: copied})
}

func (s *Store) Get(sessionID string) (Session, bool) {
	if s == nil || sessionID == "" {
		return Session{}, false
	}
	v, ok := s.Load(sessionID)
	if !ok {
		return Session{}, false
	}
	session, ok := v.(Session)
	return session, ok
}

func (s *Store) Delete(sessionID string) {
	if s == nil || sessionID == "" {
		return
	}
	s.Map.Delete(sessionID)
}

// GetIDFromContext retrieves the session ID from request context
func GetIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(ContextKey).(string)
	return id
}

// ContextWithID returns a new context with the session ID set
func ContextWithID(ctx context.Context, sessionID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, ContextKey, sessionID)
}
