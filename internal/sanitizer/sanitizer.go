package sanitizer

import (
	"sort"
	"strconv"
	"strings"
)

type Detector interface {
	Name() string
	Detect(text string) []Match
}

type Match struct {
	Type       string
	Value      string
	Start      int
	End        int
	Confidence float64
}

type SanitizedItem struct {
	Type        string
	Original    string
	Placeholder string
}

type Sanitizer struct {
	detectors           []Detector
	confidenceThreshold float64
	maxReplacements     int
}

func New(detectors []Detector) *Sanitizer {
	return &Sanitizer{detectors: detectors, confidenceThreshold: 0.0}
}

func (s *Sanitizer) WithConfidenceThreshold(v float64) *Sanitizer {
	s.confidenceThreshold = v
	return s
}

func (s *Sanitizer) WithMaxReplacements(v int) *Sanitizer {
	s.maxReplacements = v
	return s
}

func (s *Sanitizer) Sanitize(input string) (string, []SanitizedItem) {
	if s == nil || len(s.detectors) == 0 || input == "" {
		return input, nil
	}

	all := make([]Match, 0)
	for _, d := range s.detectors {
		for _, m := range d.Detect(input) {
			if m.Confidence < s.confidenceThreshold {
				continue
			}
			if m.Start < 0 || m.End > len(input) || m.Start >= m.End {
				continue
			}
			all = append(all, m)
		}
	}
	if len(all) == 0 {
		return input, nil
	}

	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Start == all[j].Start {
			return all[i].End > all[j].End
		}
		return all[i].Start < all[j].Start
	})

	typeCounters := map[string]int{}
	placeholdersByValue := map[string]string{}
	itemsByPlaceholder := map[string]SanitizedItem{}
	chosen := make([]Match, 0, len(all))

	lastEnd := -1
	for _, m := range all {
		if m.Start < lastEnd {
			continue
		}
		lastEnd = m.End
		chosen = append(chosen, m)
	}

	var out strings.Builder
	cursor := 0
	replacements := 0
	for _, m := range chosen {
		if s.maxReplacements > 0 && replacements >= s.maxReplacements {
			break
		}
		key := m.Type + "|" + m.Value
		placeholder, exists := placeholdersByValue[key]
		if !exists {
			typeCounters[m.Type]++
			placeholder = "[" + strings.ToUpper(m.Type) + "_" + strconv.Itoa(typeCounters[m.Type]) + "]"
			placeholdersByValue[key] = placeholder
			itemsByPlaceholder[placeholder] = SanitizedItem{Type: m.Type, Original: m.Value, Placeholder: placeholder}
		}
		out.WriteString(input[cursor:m.Start])
		out.WriteString(placeholder)
		cursor = m.End
		replacements++
	}
	out.WriteString(input[cursor:])

	items := make([]SanitizedItem, 0, len(itemsByPlaceholder))
	for _, item := range itemsByPlaceholder {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Placeholder < items[j].Placeholder })
	return out.String(), items
}

func Restore(text string, items []SanitizedItem) string {
	restored := text
	for _, item := range items {
		restored = strings.ReplaceAll(restored, item.Placeholder, item.Original)
	}
	return restored
}
