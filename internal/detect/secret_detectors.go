package detect

import (
	"encoding/json"
	"regexp"
	"strings"
)

var (
	awsAccessKeyIDRegexp  = regexp.MustCompile(`\bAKIA[A-Z0-9]{16}\b`)
	awsSecretKeyRegexp    = regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`)
	awsSessionTokenRegexp = regexp.MustCompile(`\b(?:AQoDYXdz|IQoJb3JpZ2luX2Vj)[A-Za-z0-9/+=]{20,}\b`)

	gcpAPIKeyRegexp        = regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35,40}\b`)
	gcpServiceAccountRegex = regexp.MustCompile(`(?s)\{.*?"type"\s*:\s*"service_account".*?"private_key"\s*:\s*".*?BEGIN PRIVATE KEY.*?END PRIVATE KEY.*?".*?"client_email"\s*:\s*".+?".*?\}`)

	azureConnectionStringRegexp = regexp.MustCompile(`(?i)\bDefaultEndpointsProtocol=https;AccountName=[^;\s]+;AccountKey=[^;\s]+;EndpointSuffix=[^;\s]+\b`)
	azureSASTokenRegexp         = regexp.MustCompile(`\bsv=[^\s&]+&ss=[^\s&]+&srt=[^\s&]+&sp=[^\s&]+&se=[^\s&]+&st=[^\s&]+&spr=[^\s&]+&sig=[^\s&]+\b`)

	privateKeyRegexp = regexp.MustCompile(`(?s)-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) PRIVATE KEY-----.*?-----END (?:RSA|DSA|EC|OPENSSH|PRIVATE) PRIVATE KEY-----`)

	databaseURLRegexp = regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mongodb|redis)://[^\s"']+`)

	hexSecretRegexp = regexp.MustCompile(`\b[a-fA-F0-9]{32,}\b`)
	highEntropyWord = regexp.MustCompile(`\b[A-Za-z0-9+/=_\-]{32,}\b`)
)

type SecretMatch struct {
	Type  string
	Value string
	Start int
	End   int
	Score float64
}

func FindSecretMatches(text string) []SecretMatch {
	out := make([]SecretMatch, 0)
	out = append(out, findSimple(text, awsAccessKeyIDRegexp, "AWS_ACCESS_KEY", 0.99)...)
	out = append(out, findAWSSecretKeys(text)...)
	out = append(out, findSimple(text, awsSessionTokenRegexp, "AWS_SESSION_TOKEN", 0.9)...)
	out = append(out, findSimple(text, gcpAPIKeyRegexp, "GCP_API_KEY", 0.97)...)
	out = append(out, findGCPServiceAccounts(text)...)
	out = append(out, findSimple(text, azureConnectionStringRegexp, "AZURE_CONNECTION_STRING", 0.98)...)
	out = append(out, findSimple(text, azureSASTokenRegexp, "AZURE_SAS_TOKEN", 0.95)...)
	out = append(out, findSimple(text, privateKeyRegexp, "PRIVATE_KEY", 1.0)...)
	out = append(out, findDatabaseURLs(text)...)
	out = append(out, findSimple(text, hexSecretRegexp, "HEX_SECRET", 0.75)...)
	out = append(out, findHighEntropy(text)...)
	return out
}

func SecretMatchesToEntities(matches []SecretMatch) []Entity {
	entities := make([]Entity, 0, len(matches))
	for _, m := range matches {
		entities = append(entities, Entity{Type: m.Type, Start: m.Start, End: m.End, Score: m.Score, Source: "regex"})
	}
	return entities
}

func findSimple(text string, re *regexp.Regexp, typ string, score float64) []SecretMatch {
	idxs := re.FindAllStringIndex(text, -1)
	out := make([]SecretMatch, 0, len(idxs))
	for _, idx := range idxs {
		out = append(out, SecretMatch{Type: typ, Value: text[idx[0]:idx[1]], Start: idx[0], End: idx[1], Score: score})
	}
	return out
}

func findAWSSecretKeys(text string) []SecretMatch {
	idxs := awsSecretKeyRegexp.FindAllStringIndex(text, -1)
	out := make([]SecretMatch, 0, len(idxs))
	for _, idx := range idxs {
		candidate := text[idx[0]:idx[1]]
		if ShannonEntropy(candidate) < 4.0 {
			continue
		}
		out = append(out, SecretMatch{Type: "AWS_SECRET_KEY", Value: candidate, Start: idx[0], End: idx[1], Score: 0.88})
	}
	return out
}

func findGCPServiceAccounts(text string) []SecretMatch {
	idxs := gcpServiceAccountRegex.FindAllStringIndex(text, -1)
	out := make([]SecretMatch, 0, len(idxs))
	for _, idx := range idxs {
		candidate := text[idx[0]:idx[1]]
		if !looksLikeServiceAccountJSON(candidate) {
			continue
		}
		out = append(out, SecretMatch{Type: "GCP_SERVICE_ACCOUNT", Value: candidate, Start: idx[0], End: idx[1], Score: 1.0})
	}
	return out
}

func looksLikeServiceAccountJSON(s string) bool {
	var payload map[string]any
	if err := json.Unmarshal([]byte(s), &payload); err != nil {
		return false
	}
	return strings.EqualFold(toString(payload["type"]), "service_account") &&
		strings.Contains(toString(payload["private_key"]), "BEGIN PRIVATE KEY") &&
		toString(payload["client_email"]) != ""
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

func findDatabaseURLs(text string) []SecretMatch {
	idxs := databaseURLRegexp.FindAllStringIndex(text, -1)
	out := make([]SecretMatch, 0, len(idxs))
	for _, idx := range idxs {
		candidate := text[idx[0]:idx[1]]
		if !strings.Contains(candidate, "@") || !strings.Contains(candidate, ":") {
			continue
		}
		out = append(out, SecretMatch{Type: "DB_URL", Value: candidate, Start: idx[0], End: idx[1], Score: 0.94})
	}
	return out
}

func findHighEntropy(text string) []SecretMatch {
	idxs := highEntropyWord.FindAllStringIndex(text, -1)
	out := make([]SecretMatch, 0, len(idxs))
	for _, idx := range idxs {
		candidate := text[idx[0]:idx[1]]
		if ShannonEntropy(candidate) < 4.5 {
			continue
		}
		out = append(out, SecretMatch{Type: "HIGH_ENTROPY", Value: candidate, Start: idx[0], End: idx[1], Score: 0.7})
	}
	return out
}
