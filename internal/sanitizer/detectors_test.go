package sanitizer

import "testing"

func TestEmailDetectorFindsEmail(t *testing.T) {
	m := EmailDetector{}.Detect("contact john@example.com now")
	if len(m) != 1 || m[0].Value != "john@example.com" {
		t.Fatalf("unexpected matches: %+v", m)
	}
}

func TestPhoneDetectorFindsPhone(t *testing.T) {
	m := PhoneDetector{}.Detect("call +123 456 7890 tomorrow")
	if len(m) != 1 {
		t.Fatalf("expected 1 phone match, got %d", len(m))
	}
}

func TestAPIKeyDetectorFindsToken(t *testing.T) {
	m := APIKeyDetector{}.Detect("key=Abcdefghij1234567890XYZ")
	if len(m) != 1 {
		t.Fatalf("expected 1 api key match, got %d", len(m))
	}
}
