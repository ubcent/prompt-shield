package detect

import (
	"os"
	"strings"
	"unicode"
)

type Token struct {
	Text       string
	Start, End int
}

type SimpleTokenizer struct {
	_ string
}

func NewSimpleTokenizer(path string) *SimpleTokenizer {
	_, _ = os.Stat(path)
	return &SimpleTokenizer{}
}

func (t *SimpleTokenizer) Tokenize(text string) ([]Token, error) {
	tokens := make([]Token, 0)
	start := -1
	for i, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			tokens = append(tokens, Token{Text: text[start:i], Start: start, End: i})
			start = -1
		}
	}
	if start >= 0 {
		tokens = append(tokens, Token{Text: text[start:], Start: start, End: len(text)})
	}
	return tokens, nil
}

func tokensToEntities(_ string, tokens []Token, labels []string, scores []float64) []Entity {
	spans := mergeBIO(tokens, labels, scores)
	out := make([]Entity, 0, len(spans))
	for _, s := range spans {
		out = append(out, Entity{Type: strings.ToUpper(s.Type), Start: s.Start, End: s.End, Score: s.Score, Source: "onnx-ner"})
	}
	return out
}

type bioSpan struct {
	Type       string
	Start, End int
	Score      float64
}

func mergeBIO(tokens []Token, labels []string, scores []float64) []bioSpan {
	out := make([]bioSpan, 0)
	var cur *bioSpan
	for i := range tokens {
		label := labels[i]
		score := scores[i]
		if label == "O" || label == "" {
			if cur != nil {
				out = append(out, *cur)
				cur = nil
			}
			continue
		}
		parts := strings.SplitN(label, "-", 2)
		if len(parts) != 2 {
			continue
		}
		prefix, typ := parts[0], parts[1]
		if prefix == "B" || cur == nil || cur.Type != typ {
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &bioSpan{Type: typ, Start: tokens[i].Start, End: tokens[i].End, Score: score}
			continue
		}
		cur.End = tokens[i].End
		cur.Score = (cur.Score + score) / 2
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}
