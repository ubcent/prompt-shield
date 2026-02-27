package sanitizer

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"velar/internal/detect"
)

// DefaultSanitizeKeys are JSON field names whose values are user content and should be inspected.
var DefaultSanitizeKeys = map[string]struct{}{
	"prompt": {}, "input": {}, "content": {}, "text": {}, "message": {}, "parts": {},
}

// DefaultSkipKeys are JSON field names whose values should never be masked (auth/service fields).
var DefaultSkipKeys = map[string]struct{}{
	"authorization": {}, "access_token": {}, "session_token": {}, "token": {},
	"bearer": {}, "id_token": {}, "refresh_token": {}, "api_key": {}, "apikey": {},
	"x-api-key": {}, "cookie": {}, "set-cookie": {},
	"model": {}, "role": {}, "type": {}, "id": {}, "object": {},
	"created": {}, "system_fingerprint": {},
}

// KeyConfig controls which JSON keys are sanitized and which are skipped.
type KeyConfig struct {
	SanitizeKeys map[string]struct{}
	SkipKeys     map[string]struct{}
}

// DefaultKeyConfig returns the default key configuration.
func DefaultKeyConfig() KeyConfig {
	return KeyConfig{
		SanitizeKeys: DefaultSanitizeKeys,
		SkipKeys:     DefaultSkipKeys,
	}
}

// NewKeyConfig creates a KeyConfig from string slices.
// If sanitizeKeys is empty, DefaultSanitizeKeys is used.
// If skipKeys is empty, DefaultSkipKeys is used.
func NewKeyConfig(sanitizeKeys, skipKeys []string) KeyConfig {
	kc := KeyConfig{
		SanitizeKeys: DefaultSanitizeKeys,
		SkipKeys:     DefaultSkipKeys,
	}
	if len(sanitizeKeys) > 0 {
		kc.SanitizeKeys = make(map[string]struct{}, len(sanitizeKeys))
		for _, k := range sanitizeKeys {
			kc.SanitizeKeys[strings.ToLower(k)] = struct{}{}
		}
	}
	if len(skipKeys) > 0 {
		kc.SkipKeys = make(map[string]struct{}, len(skipKeys))
		for _, k := range skipKeys {
			kc.SkipKeys[strings.ToLower(k)] = struct{}{}
		}
	}
	return kc
}

func (kc KeyConfig) shouldSanitize(key string) bool {
	lower := strings.ToLower(key)
	if _, skip := kc.SkipKeys[lower]; skip {
		return false
	}
	_, ok := kc.SanitizeKeys[lower]
	return ok
}

func sanitizeJSONFields(ctx context.Context, raw []byte, detector detect.Detector, maxReplacements int, kc KeyConfig) ([]byte, []SanitizedItem, error) {
	if detector == nil || len(raw) == 0 {
		return raw, nil, nil
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return raw, nil, err
	}
	repl := &replacementState{maxReplacements: maxReplacements, counters: map[string]int{}, byKey: map[string]string{}, byPlaceholder: map[string]SanitizedItem{}}
	payload = walkAndMask(ctx, payload, detector, repl, "", kc)
	out, err := json.Marshal(payload)
	if err != nil {
		return raw, nil, err
	}
	return out, repl.items(), nil
}

// sanitizeJSONFieldsWithSanitizer performs JSON-aware sanitization using the regex-based Sanitizer
// as a fallback when HybridDetector is not available or finds nothing.
// It only sanitizes values under sanitizeKeys and never touches skipKeys.
func sanitizeJSONFieldsWithSanitizer(raw []byte, s *Sanitizer, kc KeyConfig) ([]byte, []SanitizedItem, error) {
	if s == nil || len(raw) == 0 {
		return raw, nil, nil
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return raw, nil, err
	}
	repl := &replacementState{maxReplacements: s.maxReplacements, counters: map[string]int{}, byKey: map[string]string{}, byPlaceholder: map[string]SanitizedItem{}}
	payload = walkAndMaskWithSanitizer(payload, s, repl, "", kc)
	out, err := json.Marshal(payload)
	if err != nil {
		return raw, nil, err
	}
	return out, repl.items(), nil
}

type replacementState struct {
	maxReplacements int
	replacements    int
	counters        map[string]int
	byKey           map[string]string
	byPlaceholder   map[string]SanitizedItem
}

func (r *replacementState) items() []SanitizedItem {
	out := make([]SanitizedItem, 0, len(r.byPlaceholder))
	for _, item := range r.byPlaceholder {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Placeholder < out[j].Placeholder })
	return out
}

func walkAndMask(ctx context.Context, node any, detector detect.Detector, repl *replacementState, key string, kc KeyConfig) any {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			v[k] = walkAndMask(ctx, child, detector, repl, k, kc)
		}
		return v
	case []any:
		for i, child := range v {
			v[i] = walkAndMask(ctx, child, detector, repl, key, kc)
		}
		return v
	case string:
		if !kc.shouldSanitize(key) {
			return v
		}
		return applyMask(ctx, v, detector, repl)
	default:
		return node
	}
}

func walkAndMaskWithSanitizer(node any, s *Sanitizer, repl *replacementState, key string, kc KeyConfig) any {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			v[k] = walkAndMaskWithSanitizer(child, s, repl, k, kc)
		}
		return v
	case []any:
		for i, child := range v {
			v[i] = walkAndMaskWithSanitizer(child, s, repl, key, kc)
		}
		return v
	case string:
		if !kc.shouldSanitize(key) {
			return v
		}
		return applyMaskWithSanitizer(v, s, repl)
	default:
		return node
	}
}

func applyMaskWithSanitizer(input string, s *Sanitizer, repl *replacementState) string {
	_, matches := s.collectMatches(input)
	if len(matches) == 0 {
		return input
	}

	var b strings.Builder
	cursor := 0
	for _, m := range matches {
		if repl.maxReplacements > 0 && repl.replacements >= repl.maxReplacements {
			break
		}
		value := m.Value
		if strings.TrimSpace(value) == "" {
			continue
		}
		upperType := strings.ToUpper(m.Type)
		key := upperType + "|" + value
		placeholder, ok := repl.byKey[key]
		if !ok {
			repl.counters[upperType]++
			placeholder = "[" + upperType + "_" + strconv.Itoa(repl.counters[upperType]) + "]"
			repl.byKey[key] = placeholder
			repl.byPlaceholder[placeholder] = SanitizedItem{Type: strings.ToLower(upperType), Original: value, Placeholder: placeholder}
		}
		b.WriteString(input[cursor:m.Start])
		b.WriteString(placeholder)
		cursor = m.End
		repl.replacements++
	}
	b.WriteString(input[cursor:])
	return b.String()
}

func applyMask(ctx context.Context, input string, detector detect.Detector, repl *replacementState) string {
	entities, err := detector.Detect(ctx, input)
	if err != nil || len(entities) == 0 {
		return input
	}
	sort.SliceStable(entities, func(i, j int) bool {
		if entities[i].Start == entities[j].Start {
			return entities[i].End > entities[j].End
		}
		return entities[i].Start < entities[j].Start
	})
	var b strings.Builder
	cursor := 0
	lastEnd := -1
	for _, e := range entities {
		if e.Start < 0 || e.End > len(input) || e.Start >= e.End || e.Start < lastEnd {
			continue
		}
		if repl.maxReplacements > 0 && repl.replacements >= repl.maxReplacements {
			break
		}
		value := input[e.Start:e.End]
		if strings.TrimSpace(value) == "" {
			continue
		}
		upperType := strings.ToUpper(e.Type)
		key := upperType + "|" + value
		placeholder, ok := repl.byKey[key]
		if !ok {
			repl.counters[upperType]++
			placeholder = "[" + upperType + "_" + strconv.Itoa(repl.counters[upperType]) + "]"
			repl.byKey[key] = placeholder
			repl.byPlaceholder[placeholder] = SanitizedItem{Type: strings.ToLower(upperType), Original: value, Placeholder: placeholder}
		}
		b.WriteString(input[cursor:e.Start])
		b.WriteString(placeholder)
		cursor = e.End
		lastEnd = e.End
		repl.replacements++
	}
	b.WriteString(input[cursor:])
	return b.String()
}
