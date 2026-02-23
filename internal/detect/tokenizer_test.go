package detect

import "testing"

func TestTokenizerStableOutput(t *testing.T) {
	tok := NewSimpleTokenizer("")
	in := "My name is John Smith."
	out, err := tok.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 5 {
		t.Fatalf("expected 5 tokens, got %d", len(out))
	}
	if out[3].Text != "John" || out[3].Start != 11 || out[3].End != 15 {
		t.Fatalf("unexpected token mapping: %+v", out[3])
	}
}

func TestMergeBIO(t *testing.T) {
	tokens := []Token{{Text: "John", Start: 0, End: 4}, {Text: "Smith", Start: 5, End: 10}, {Text: "Acme", Start: 14, End: 18}}
	labels := []string{"B-PERSON", "I-PERSON", "B-ORG"}
	scores := []float64{0.9, 0.8, 0.85}
	spans := mergeBIO(tokens, labels, scores)
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
	if spans[0].Start != 0 || spans[0].End != 10 || spans[0].Type != "PERSON" {
		t.Fatalf("unexpected span %#v", spans[0])
	}
}
