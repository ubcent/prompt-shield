package sanitizer

import "testing"

func TestSanitizer_SecretPlaceholders(t *testing.T) {
	s := New(DetectorsByName([]string{"aws_access_key", "db_url", "private_key"}))
	in := "AKIAIOSFODNN7EXAMPLE postgresql://user:pass@db.example.com:5432/mydb -----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
	out, items := s.Sanitize(in)
	if len(items) < 3 {
		t.Fatalf("expected 3+ items, got %d (%q)", len(items), out)
	}
	if out == in {
		t.Fatalf("expected sanitized output to differ")
	}
}
