package sanitizer

import (
	"strings"
	"testing"
)

func TestSanitizerReplacesValues(t *testing.T) {
	s := New([]Detector{EmailDetector{}, PhoneDetector{}})
	out, items := s.Sanitize("email john@example.com phone +123 456 7890")
	if !strings.Contains(out, "[EMAIL_1]") || !strings.Contains(out, "[PHONE_1]") {
		t.Fatalf("unexpected output: %q", out)
	}
	if len(items) != 2 {
		t.Fatalf("items=%d want 2", len(items))
	}
}

func TestSanitizerSameValueSamePlaceholder(t *testing.T) {
	s := New([]Detector{EmailDetector{}})
	out, items := s.Sanitize("john@example.com and john@example.com")
	if strings.Count(out, "[EMAIL_1]") != 2 {
		t.Fatalf("expected placeholder reused, got %q", out)
	}
	if len(items) != 1 {
		t.Fatalf("items=%d want 1", len(items))
	}
}

func TestRestore(t *testing.T) {
	orig := "send to john@example.com"
	s := New([]Detector{EmailDetector{}})
	san, items := s.Sanitize(orig)
	if Restore(san, items) != orig {
		t.Fatalf("restore mismatch: %q", Restore(san, items))
	}
}
