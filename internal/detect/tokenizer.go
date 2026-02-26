package detect

import (
	"encoding/json"
	"fmt"
	"math"
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

func (t *SimpleTokenizer) Tokenize(text string) ([]Token, error) {
	return splitWordsWithOffsets(text), nil
}

type WordPieceTokenizer struct {
	vocab      map[string]int
	unkID      int
	clsID      int
	sepID      int
	maxWordLen int
	maxSeqLen  int
	lowercase  bool
}

type TokenizerOutput struct {
	InputIDs       []int64
	AttentionMask  []int64
	TokenTypeIDs   []int64
	TokenToWordIdx []int
	Words          []Token
}

type tokenizerJSON struct {
	Model struct {
		Vocab map[string]int `json:"vocab"`
	} `json:"model"`
	Normalizer struct {
		Lowercase *bool `json:"lowercase"`
	} `json:"normalizer"`
}

func NewWordPieceTokenizer(tokenizerPath string) (*WordPieceTokenizer, error) {
	vocab, lowercase, err := loadTokenizerConfig(tokenizerPath)
	if err != nil {
		return nil, err
	}
	unkID, ok := vocab["[UNK]"]
	if !ok {
		return nil, fmt.Errorf("tokenizer vocab is missing [UNK]")
	}
	clsID, ok := vocab["[CLS]"]
	if !ok {
		return nil, fmt.Errorf("tokenizer vocab is missing [CLS]")
	}
	sepID, ok := vocab["[SEP]"]
	if !ok {
		return nil, fmt.Errorf("tokenizer vocab is missing [SEP]")
	}
	return &WordPieceTokenizer{vocab: vocab, unkID: unkID, clsID: clsID, sepID: sepID, maxWordLen: 100, maxSeqLen: 512, lowercase: lowercase}, nil
}

func loadTokenizerConfig(path string) (map[string]int, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	var cfg tokenizerJSON
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, false, err
	}
	if len(cfg.Model.Vocab) == 0 {
		return nil, false, fmt.Errorf("tokenizer.json model.vocab is empty")
	}
	lowercase := true
	if cfg.Normalizer.Lowercase != nil {
		lowercase = *cfg.Normalizer.Lowercase
	}
	return cfg.Model.Vocab, lowercase, nil
}

func (t *WordPieceTokenizer) Encode(text string) (*TokenizerOutput, error) {
	words := splitWordsWithOffsets(text)
	out := &TokenizerOutput{
		InputIDs:       []int64{int64(t.clsID)},
		AttentionMask:  []int64{1},
		TokenTypeIDs:   []int64{0},
		TokenToWordIdx: []int{-1},
		Words:          words,
	}
	for wi, word := range words {
		tokens := t.wordToPieces(word.Text)
		for _, pieceID := range tokens {
			if len(out.InputIDs) >= t.maxSeqLen-1 {
				break
			}
			out.InputIDs = append(out.InputIDs, int64(pieceID))
			out.AttentionMask = append(out.AttentionMask, 1)
			out.TokenTypeIDs = append(out.TokenTypeIDs, 0)
			out.TokenToWordIdx = append(out.TokenToWordIdx, wi)
		}
		if len(out.InputIDs) >= t.maxSeqLen-1 {
			break
		}
	}
	out.InputIDs = append(out.InputIDs, int64(t.sepID))
	out.AttentionMask = append(out.AttentionMask, 1)
	out.TokenTypeIDs = append(out.TokenTypeIDs, 0)
	out.TokenToWordIdx = append(out.TokenToWordIdx, -1)
	return out, nil
}

func (t *WordPieceTokenizer) wordToPieces(word string) []int {
	if word == "" {
		return []int{t.unkID}
	}
	normalized := word
	if t.lowercase {
		normalized = strings.ToLower(word)
	}
	runes := []rune(normalized)
	if len(runes) > t.maxWordLen {
		return []int{t.unkID}
	}
	full := string(runes)
	if id, ok := t.vocab[full]; ok {
		return []int{id}
	}
	ids := make([]int, 0)
	start := 0
	for start < len(runes) {
		end := len(runes)
		found := -1
		for end > start {
			piece := string(runes[start:end])
			if start > 0 {
				piece = "##" + piece
			}
			if id, ok := t.vocab[piece]; ok {
				found = id
				break
			}
			end--
		}
		if found == -1 {
			return []int{t.unkID}
		}
		ids = append(ids, found)
		start = end
	}
	if len(ids) == 0 {
		return []int{t.unkID}
	}
	return ids
}

func splitWordsWithOffsets(text string) []Token {
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
	return tokens
}

func tokensToEntities(tokens []Token, labels []string, scores []float64) []Entity {
	spans := mergeBIO(tokens, labels, scores)
	out := make([]Entity, 0, len(spans))
	for _, s := range spans {
		out = append(out, Entity{Type: mapNERType(s.Type), Start: s.Start, End: s.End, Score: s.Score, Source: "onnx-ner"})
	}
	return out
}

func mapNERType(t string) string {
	switch strings.ToUpper(t) {
	case "PER", "PERSON":
		return "PERSON"
	case "ORG":
		return "ORG"
	case "LOC", "GPE":
		return "LOC"
	case "MISC":
		return "MISC"
	default:
		return strings.ToUpper(t)
	}
}

type bioSpan struct {
	Type       string
	Start, End int
	Score      float64
}

func mergeBIO(tokens []Token, labels []string, scores []float64) []bioSpan {
	out := make([]bioSpan, 0)
	var cur *bioSpan
	curCount := 0.0
	for i := range tokens {
		label := labels[i]
		score := scores[i]
		if label == "O" || label == "" {
			if cur != nil {
				cur.Score = cur.Score / math.Max(1, curCount)
				out = append(out, *cur)
				cur = nil
				curCount = 0
			}
			continue
		}
		parts := strings.SplitN(label, "-", 2)
		if len(parts) != 2 {
			continue
		}
		prefix, typ := parts[0], parts[1]
		if prefix != "I" && prefix != "B" {
			continue
		}
		if prefix == "B" || cur == nil || cur.Type != typ {
			if cur != nil {
				cur.Score = cur.Score / math.Max(1, curCount)
				out = append(out, *cur)
			}
			cur = &bioSpan{Type: typ, Start: tokens[i].Start, End: tokens[i].End, Score: score}
			curCount = 1
			continue
		}
		cur.End = tokens[i].End
		cur.Score += score
		curCount++
	}
	if cur != nil {
		cur.Score = cur.Score / math.Max(1, curCount)
		out = append(out, *cur)
	}
	return out
}
