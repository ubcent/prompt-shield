package sanitizer

import (
	"context"
	"strings"
	"testing"

	"velar/internal/detect"
)

type fakeNER struct{}

func (fakeNER) Detect(_ context.Context, text string) ([]detect.Entity, error) {
	if text == "My name is John Smith and I work at Acme Corp in Amsterdam." {
		return []detect.Entity{
			{Type: "PERSON", Start: 11, End: 21, Score: 0.95, Source: "onnx-ner"},
			{Type: "ORG", Start: 36, End: 45, Score: 0.9, Source: "onnx-ner"},
			{Type: "LOC", Start: 49, End: 58, Score: 0.9, Source: "onnx-ner"},
		}, nil
	}
	return nil, nil
}

func TestSanitizeJSONFieldsWithNER(t *testing.T) {
	h := detect.HybridDetector{Fast: []detect.Detector{detect.RegexDetector{}}, Ner: fakeNER{}, Config: detect.HybridConfig{NerEnabled: true, MinScore: 0.7}}
	input := []byte(`{"prompt":"My name is John Smith and I work at Acme Corp in Amsterdam."}`)
	out, items, err := sanitizeJSONFields(context.Background(), input, h, 10, DefaultKeyConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	want := `{"prompt":"My name is [PERSON_1] and I work at [ORG_1] in [LOC_1]."}`
	if got != want {
		t.Fatalf("want %s got %s", want, got)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}
}

func TestSanitizeJSONFields_InterestingAndUninterestingKeys(t *testing.T) {
	h := detect.HybridDetector{Fast: []detect.Detector{detect.RegexDetector{}}, Config: detect.HybridConfig{NerEnabled: false}}
	input := []byte(`{"content":"contact alice@example.com","metadata":"alice@example.com"}`)
	out, items, err := sanitizeJSONFields(context.Background(), input, h, 0, DefaultKeyConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, `"content":"contact [EMAIL_1]"`) {
		t.Fatalf("expected content key to be sanitized, got %s", got)
	}
	if !strings.Contains(got, `"metadata":"alice@example.com"`) {
		t.Fatalf("expected metadata key to remain untouched, got %s", got)
	}
	if len(items) != 1 {
		t.Fatalf("expected one sanitized item, got %+v", items)
	}
}

func TestSanitizeJSONFields_NestedContent(t *testing.T) {
	h := detect.HybridDetector{Fast: []detect.Detector{detect.RegexDetector{}}, Config: detect.HybridConfig{NerEnabled: false}}
	input := []byte(`{"messages":[{"role":"user","content":"alice@example.com"}]}`)
	out, items, err := sanitizeJSONFields(context.Background(), input, h, 0, DefaultKeyConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"content":"[EMAIL_1]"`) {
		t.Fatalf("expected nested content to be sanitized, got %s", string(out))
	}
	if len(items) != 1 {
		t.Fatalf("expected one item, got %+v", items)
	}
}

func TestSanitizeJSONFields_NonJSONBody(t *testing.T) {
	h := detect.HybridDetector{Fast: []detect.Detector{detect.RegexDetector{}}, Config: detect.HybridConfig{NerEnabled: false}}
	input := []byte("plain text with alice@example.com")
	out, items, err := sanitizeJSONFields(context.Background(), input, h, 0, DefaultKeyConfig())
	if err == nil {
		t.Fatalf("expected JSON parse error, got out=%q items=%+v", string(out), items)
	}
}

func TestSanitizeJSONFields_SkipKeysProtectsAuthFields(t *testing.T) {
	h := detect.HybridDetector{Fast: []detect.Detector{detect.RegexDetector{}}, Config: detect.HybridConfig{NerEnabled: false}}
	// "access_token" is in DefaultSkipKeys, so even if it contains a secret-like value, it must not be masked
	input := []byte(`{"content":"alice@example.com","access_token":"sk-Abcdefghij1234567890XYZ","model":"gpt-4"}`)
	out, items, err := sanitizeJSONFields(context.Background(), input, h, 0, DefaultKeyConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, `"content":"[EMAIL_1]"`) {
		t.Fatalf("expected content to be sanitized, got %s", got)
	}
	if !strings.Contains(got, `"access_token":"sk-Abcdefghij1234567890XYZ"`) {
		t.Fatalf("expected access_token to remain untouched, got %s", got)
	}
	if !strings.Contains(got, `"model":"gpt-4"`) {
		t.Fatalf("expected model to remain untouched, got %s", got)
	}
	if len(items) != 1 {
		t.Fatalf("expected one sanitized item, got %+v", items)
	}
}

func TestSanitizeJSONFields_CustomKeyConfig(t *testing.T) {
	h := detect.HybridDetector{Fast: []detect.Detector{detect.RegexDetector{}}, Config: detect.HybridConfig{NerEnabled: false}}
	kc := NewKeyConfig([]string{"custom_field"}, []string{"content"})
	input := []byte(`{"content":"alice@example.com","custom_field":"bob@example.com"}`)
	out, items, err := sanitizeJSONFields(context.Background(), input, h, 0, kc)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, `"content":"alice@example.com"`) {
		t.Fatalf("expected content to be skipped (in skip_keys), got %s", got)
	}
	if !strings.Contains(got, `"custom_field":"[EMAIL_1]"`) {
		t.Fatalf("expected custom_field to be sanitized, got %s", got)
	}
	if len(items) != 1 {
		t.Fatalf("expected one sanitized item, got %+v", items)
	}
}

func TestSanitizeJSONFieldsWithSanitizer_FallbackJSONAware(t *testing.T) {
	s := New([]Detector{EmailDetector{}})
	input := []byte(`{"messages":[{"role":"user","content":"contact alice@example.com"}],"token":"sk-Abcdefghij1234567890XYZ"}`)
	out, items, err := sanitizeJSONFieldsWithSanitizer(input, s, DefaultKeyConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, `"content":"contact [EMAIL_1]"`) {
		t.Fatalf("expected content to be sanitized, got %s", got)
	}
	if !strings.Contains(got, `"token":"sk-Abcdefghij1234567890XYZ"`) {
		t.Fatalf("expected token to remain untouched, got %s", got)
	}
	if !strings.Contains(got, `"role":"user"`) {
		t.Fatalf("expected role to remain untouched, got %s", got)
	}
	if len(items) != 1 {
		t.Fatalf("expected one sanitized item, got %+v", items)
	}
}

func TestSanitizeJSONFieldsWithSanitizer_NonJSONFallback(t *testing.T) {
	s := New([]Detector{EmailDetector{}})
	input := []byte("plain text alice@example.com")
	_, _, err := sanitizeJSONFieldsWithSanitizer(input, s, DefaultKeyConfig())
	if err == nil {
		t.Fatal("expected error for non-JSON input")
	}
}
