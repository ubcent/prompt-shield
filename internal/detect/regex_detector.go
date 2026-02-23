package detect

import (
	"context"
	"encoding/base64"
	"math"
	"regexp"
	"strings"
	"unicode"
)

var (
	emailRegexp = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	phoneRegexp = regexp.MustCompile(`\+?\d[\d\s\-]{7,}`)
	tokenRegexp = regexp.MustCompile(`\b[A-Za-z0-9_\-]{20,}\b`)
	jwtRegexp   = regexp.MustCompile(`\b[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`)
)

type RegexDetector struct{}

func (RegexDetector) Detect(_ context.Context, text string) ([]Entity, error) {
	out := make([]Entity, 0)
	out = append(out, findRegexMatches(text, emailRegexp, "EMAIL", 0.99)...)
	out = append(out, findRegexMatches(text, phoneRegexp, "PHONE", 0.95)...)
	out = append(out, findAPIKeys(text)...)
	out = append(out, findJWTs(text)...)
	return out, nil
}

func findRegexMatches(text string, re *regexp.Regexp, typ string, score float64) []Entity {
	indexes := re.FindAllStringIndex(text, -1)
	entities := make([]Entity, 0, len(indexes))
	for _, idx := range indexes {
		entities = append(entities, Entity{Type: typ, Start: idx[0], End: idx[1], Score: score, Source: "regex"})
	}
	return entities
}

func findAPIKeys(text string) []Entity {
	indexes := tokenRegexp.FindAllStringIndex(text, -1)
	entities := make([]Entity, 0, len(indexes))
	for _, idx := range indexes {
		candidate := text[idx[0]:idx[1]]
		if !hasAlphaNum(candidate) || entropy(candidate) < 3.2 {
			continue
		}
		entities = append(entities, Entity{Type: "API_KEY", Start: idx[0], End: idx[1], Score: 0.8, Source: "regex"})
	}
	return entities
}

func findJWTs(text string) []Entity {
	indexes := jwtRegexp.FindAllStringIndex(text, -1)
	entities := make([]Entity, 0, len(indexes))
	for _, idx := range indexes {
		candidate := text[idx[0]:idx[1]]
		if !looksLikeJWT(candidate) {
			continue
		}
		entities = append(entities, Entity{Type: "JWT", Start: idx[0], End: idx[1], Score: 0.9, Source: "regex"})
	}
	return entities
}

func hasAlphaNum(s string) bool {
	hasDigit, hasLetter := false, false
	for _, r := range s {
		if unicode.IsDigit(r) {
			hasDigit = true
		}
		if unicode.IsLetter(r) {
			hasLetter = true
		}
	}
	return hasDigit && hasLetter
}

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	length := float64(len(s))
	var res float64
	for _, count := range freq {
		p := count / length
		res -= p * math.Log2(p)
	}
	return res
}

func looksLikeJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for i, p := range parts {
		if p == "" {
			return false
		}
		if _, err := base64.RawURLEncoding.DecodeString(p); err != nil {
			if i == 2 {
				continue
			}
			return false
		}
	}
	return true
}
