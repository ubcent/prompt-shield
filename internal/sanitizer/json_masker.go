package sanitizer

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"velar/internal/detect"
)

var interestingKeys = map[string]struct{}{
	"prompt": {}, "input": {}, "content": {}, "text": {}, "message": {}, "parts": {},
}

func sanitizeJSONFields(ctx context.Context, raw []byte, detector detect.Detector, maxReplacements int) ([]byte, []SanitizedItem, error) {
	if detector == nil || len(raw) == 0 {
		return raw, nil, nil
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return raw, nil, err
	}
	repl := &replacementState{maxReplacements: maxReplacements, counters: map[string]int{}, byKey: map[string]string{}, byPlaceholder: map[string]SanitizedItem{}}
	payload = walkAndMask(ctx, payload, detector, repl, "")
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

func walkAndMask(ctx context.Context, node any, detector detect.Detector, repl *replacementState, key string) any {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			v[k] = walkAndMask(ctx, child, detector, repl, k)
		}
		return v
	case []any:
		for i, child := range v {
			v[i] = walkAndMask(ctx, child, detector, repl, key)
		}
		return v
	case string:
		if _, ok := interestingKeys[strings.ToLower(key)]; !ok {
			return v
		}
		return applyMask(ctx, v, detector, repl)
	default:
		return node
	}
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
