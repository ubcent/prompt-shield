package sanitizer

import (
	"context"
	"testing"

	"promptshield/internal/detect"
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
	out, items, err := sanitizeJSONFields(context.Background(), input, h, 10)
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
