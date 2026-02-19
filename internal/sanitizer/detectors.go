package sanitizer

import (
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

type EmailDetector struct{}

func (EmailDetector) Name() string { return "email" }

func (EmailDetector) Detect(text string) []Match {
	return findRegexMatches(text, emailRegexp, "email", 0.99)
}

type PhoneDetector struct{}

func (PhoneDetector) Name() string { return "phone" }

func (PhoneDetector) Detect(text string) []Match {
	return findRegexMatches(text, phoneRegexp, "phone", 0.95)
}

type APIKeyDetector struct{}

func (APIKeyDetector) Name() string { return "api_key" }

func (APIKeyDetector) Detect(text string) []Match {
	indexes := tokenRegexp.FindAllStringIndex(text, -1)
	matches := make([]Match, 0, len(indexes))
	for _, idx := range indexes {
		candidate := text[idx[0]:idx[1]]
		if !hasAlphaNum(candidate) {
			continue
		}
		if entropy(candidate) < 3.2 {
			continue
		}
		matches = append(matches, Match{Type: "api_key", Value: candidate, Start: idx[0], End: idx[1], Confidence: 0.8})
	}
	return matches
}

type JWTDetector struct{}

func (JWTDetector) Name() string { return "jwt" }

func (JWTDetector) Detect(text string) []Match {
	indexes := jwtRegexp.FindAllStringIndex(text, -1)
	matches := make([]Match, 0, len(indexes))
	for _, idx := range indexes {
		candidate := text[idx[0]:idx[1]]
		if !looksLikeJWT(candidate) {
			continue
		}
		matches = append(matches, Match{Type: "jwt", Value: candidate, Start: idx[0], End: idx[1], Confidence: 0.9})
	}
	return matches
}

func findRegexMatches(text string, re *regexp.Regexp, typ string, confidence float64) []Match {
	indexes := re.FindAllStringIndex(text, -1)
	matches := make([]Match, 0, len(indexes))
	for _, idx := range indexes {
		matches = append(matches, Match{Type: typ, Value: text[idx[0]:idx[1]], Start: idx[0], End: idx[1], Confidence: confidence})
	}
	return matches
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
