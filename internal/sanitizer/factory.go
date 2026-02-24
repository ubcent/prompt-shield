package sanitizer

import "strings"

func DetectorsByName(names []string) []Detector {
	if len(names) == 0 {
		return []Detector{EmailDetector{}, PhoneDetector{}, APIKeyDetector{}, JWTDetector{}, SecretDetector{}}
	}
	out := make([]Detector, 0, len(names))
	addedSecret := false
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
		case "secret", "aws_access_key", "aws_secret_key", "aws_session_token", "gcp_api_key", "gcp_service_account", "azure_connection_string", "azure_sas_token", "private_key", "db_url", "high_entropy", "hex_secret":
			if !addedSecret {
				out = append(out, SecretDetector{})
				addedSecret = true
			}
		}
	}
	return out
}
