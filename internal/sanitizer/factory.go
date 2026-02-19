package sanitizer

import "strings"

func DetectorsByName(names []string) []Detector {
	if len(names) == 0 {
		return []Detector{EmailDetector{}, PhoneDetector{}, APIKeyDetector{}, JWTDetector{}}
	}
	out := make([]Detector, 0, len(names))
	for _, name := range names {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "email":
			out = append(out, EmailDetector{})
		case "phone":
			out = append(out, PhoneDetector{})
		case "api_key":
			out = append(out, APIKeyDetector{})
		case "jwt":
			out = append(out, JWTDetector{})
		}
	}
	return out
}
