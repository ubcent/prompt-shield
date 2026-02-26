package detect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func baseVocab() map[string]int {
	return map[string]int{"[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3, "hello": 4, "un": 5, "##happiness": 6, "john": 7, "smith": 8, "works": 9}
}

func TestWordPiece_KnownWord(t *testing.T) {
	v := baseVocab()
	tok, err := NewWordPieceTokenizer(writeTokenizerFile(t, v))
	if err != nil {
		t.Fatal(err)
	}
	out, err := tok.Encode("hello")
	if err != nil {
		t.Fatal(err)
	}
	if got := out.InputIDs[1]; got != int64(v["hello"]) {
		t.Fatalf("got %d", got)
	}
}

func TestWordPiece_SubwordSplit(t *testing.T) {
	v := baseVocab()
	tok, _ := NewWordPieceTokenizer(writeTokenizerFile(t, v))
	out, _ := tok.Encode("unhappiness")
	if len(out.InputIDs) < 4 {
		t.Fatalf("expected subwords")
	}
	if out.InputIDs[1] != int64(v["un"]) || out.InputIDs[2] != int64(v["##happiness"]) {
		t.Fatalf("bad split: %v", out.InputIDs)
	}
}

func TestWordPiece_UnknownWord(t *testing.T) {
	v := baseVocab()
	tok, _ := NewWordPieceTokenizer(writeTokenizerFile(t, v))
	out, _ := tok.Encode("xyzqwerty12345")
	if out.InputIDs[1] != int64(v["[UNK]"]) {
		t.Fatalf("expected unk")
	}
}

func TestWordPiece_SpecialTokens(t *testing.T) {
	v := baseVocab()
	tok, _ := NewWordPieceTokenizer(writeTokenizerFile(t, v))
	out, _ := tok.Encode("hello")
	if out.InputIDs[0] != int64(v["[CLS]"]) || out.InputIDs[len(out.InputIDs)-1] != int64(v["[SEP]"]) {
		t.Fatal("missing specials")
	}
}

func TestWordPiece_CharacterOffsets(t *testing.T) {
	tok, _ := NewWordPieceTokenizer(writeTokenizerFile(t, baseVocab()))
	in := "John Smith works"
	out, _ := tok.Encode(in)
	for _, wi := range out.TokenToWordIdx {
		if wi < 0 {
			continue
		}
		w := out.Words[wi]
		if w.Start < 0 || w.End > len(in) || w.Start >= w.End {
			t.Fatalf("bad offset %+v", w)
		}
	}
}

func TestWordPiece_MaxSequenceLength(t *testing.T) {
	tok, _ := NewWordPieceTokenizer(writeTokenizerFile(t, baseVocab()))
	in := strings.Repeat("hello ", 1000)
	out, _ := tok.Encode(in)
	if len(out.InputIDs) > 512 {
		t.Fatalf("too long: %d", len(out.InputIDs))
	}
}

func TestWordPiece_EmptyInput(t *testing.T) {
	v := baseVocab()
	tok, _ := NewWordPieceTokenizer(writeTokenizerFile(t, v))
	out, _ := tok.Encode("")
	if len(out.InputIDs) != 2 {
		t.Fatalf("len=%d", len(out.InputIDs))
	}
}

func TestMergeBIO(t *testing.T) {
	tokens := []Token{{Text: "John", Start: 0, End: 4}, {Text: "Smith", Start: 5, End: 10}, {Text: "Acme", Start: 14, End: 18}}
	labels := []string{"B-PER", "I-PER", "B-ORG"}
	scores := []float64{0.9, 0.8, 0.85}
	spans := mergeBIO(tokens, labels, scores)
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
	if spans[0].Start != 0 || spans[0].End != 10 || spans[0].Type != "PER" {
		t.Fatalf("unexpected span %#v", spans[0])
	}
}

func writeTokenizerFile(t *testing.T, vocab map[string]int) string {
	t.Helper()
	d := t.TempDir()
	p := filepath.Join(d, "tokenizer.json")
	builder := strings.Builder{}
	builder.WriteString("{\"model\":{\"vocab\":{")
	i := 0
	for k, v := range vocab {
		if i > 0 {
			builder.WriteString(",")
		}
		builder.WriteString("\"")
		builder.WriteString(k)
		builder.WriteString("\":")
		builder.WriteString(strconv.Itoa(v))
		i++
	}
	builder.WriteString("}}}")
	if err := os.WriteFile(p, []byte(builder.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
