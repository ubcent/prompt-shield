package detect

import (
	"context"
	"strings"
	"testing"
)

func TestFindSecretMatches_ByType(t *testing.T) {
	input := strings.Join([]string{
		"aws_access=AKIAIOSFODNN7EXAMPLE",
		"aws_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"gcp=AIzaSyA-BCdefghijklmnopqrstuvwxyz_1234567",
		`svc={"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----\\n","client_email":"bot@example.iam.gserviceaccount.com"}`,
		"azure=DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abc123==;EndpointSuffix=core.windows.net",
		"sas=sv=2020-08-04&ss=b&srt=sco&sp=rwdlacx&se=2027-01-01T00:00:00Z&st=2026-01-01T00:00:00Z&spr=https&sig=abc",
		"pk=-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
		"db=postgresql://user:pass@db.example.com:5432/mydb",
		"hex=7d8a9f2b1c3e4f5a6b7c8d9e0f1a2b3c",
		"entropy=7d8a9f2b1c3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
	}, "\n")

	got := FindSecretMatches(input)
	seen := map[string]bool{}
	for _, m := range got {
		seen[m.Type] = true
	}
	for _, typ := range []string{"AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GCP_API_KEY", "GCP_SERVICE_ACCOUNT", "AZURE_CONNECTION_STRING", "AZURE_SAS_TOKEN", "PRIVATE_KEY", "DB_URL", "HEX_SECRET", "HIGH_ENTROPY"} {
		if !seen[typ] {
			t.Fatalf("expected type %s in matches: %+v", typ, got)
		}
	}
}

func TestRegexDetector_SecretsIncluded(t *testing.T) {
	d := RegexDetector{}
	entities, err := d.Detect(context.Background(), "token AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entities {
		if e.Type == "AWS_ACCESS_KEY" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected AWS_ACCESS_KEY in entities: %+v", entities)
	}
}

func TestFindSecretMatches_FalsePositiveRate(t *testing.T) {
	corpus := []string{
		"const AccountKey = \"not-a-secret\"",
		"variable AKIAXXXXXXXXXXXXXXXX_NAME should not match if malformed",
		"mongodb://localhost:27017 without credentials",
		"-----BEGIN PUBLIC KEY----- not private",
		"comment with sv=1&ss=2 but incomplete sas",
	}
	for i := 0; i < 50; i++ {
		corpus = append(corpus, "normal code snippet with id "+strings.Repeat("a", 10))
	}
	falsePositives := 0
	total := len(corpus)
	for _, c := range corpus {
		if len(FindSecretMatches(c)) > 0 {
			falsePositives++
		}
	}
	rate := float64(falsePositives) / float64(total)
	if rate >= 0.05 {
		t.Fatalf("false positive rate too high: %.2f", rate)
	}
}

func BenchmarkFindSecretMatches(b *testing.B) {
	text := "postgresql://user:secret123@db.example.com:5432/mydb AKIAIOSFODNN7EXAMPLE"
	for i := 0; i < b.N; i++ {
		_ = FindSecretMatches(text)
	}
}
