package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
)

var ErrNERUnavailable = errors.New("onnx ner unavailable")

type ONNXNERConfig struct {
	ModelDir string
	MaxBytes int
	MinScore float64
}

type nerSession interface {
	Run(ctx context.Context, inputIDs, attentionMask, tokenTypeIDs []int64) ([][]float32, error)
}

type ONNXNERDetector struct {
	cfg       ONNXNERConfig
	once      sync.Once
	loadErr   error
	labels    map[int]string
	tokenizer *WordPieceTokenizer
	session   nerSession
}

func NewONNXNERDetector(cfg ONNXNERConfig) *ONNXNERDetector {
	if cfg.ModelDir == "" {
		cfg.ModelDir = defaultNERModelDir()
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = 32 * 1024
	}
	return &ONNXNERDetector{cfg: cfg}
}

func defaultNERModelDir() string {
	home, err := os.UserHomeDir()
	if err == nil {
		preferred := filepath.Join(home, ".velar", "models", "ner_en")
		if _, statErr := os.Stat(filepath.Join(preferred, "model.onnx")); statErr == nil {
			return preferred
		}
	}
	return filepath.Join("internal", "models", "ner_en")
}

func (d *ONNXNERDetector) init() error {
	d.once.Do(func() {
		modelPath := filepath.Join(d.cfg.ModelDir, "model.onnx")
		labelsPath := filepath.Join(d.cfg.ModelDir, "labels.json")
		tokenizerPath := filepath.Join(d.cfg.ModelDir, "tokenizer.json")
		if _, err := os.Stat(modelPath); err != nil {
			d.loadErr = fmt.Errorf("%w: model not found at %s", ErrNERUnavailable, modelPath)
			log.Printf("[velar] onnx-ner: model not found, falling back to regex-only detection")
			return
		}
		labels, err := loadLabels(labelsPath)
		if err != nil {
			d.loadErr = fmt.Errorf("load labels: %w", err)
			return
		}
		d.labels = labels
		tok, err := NewWordPieceTokenizer(tokenizerPath)
		if err != nil {
			d.loadErr = fmt.Errorf("load tokenizer: %w", err)
			return
		}
		d.tokenizer = tok
		session, err := createONNXSession(modelPath)
		if err != nil {
			d.loadErr = fmt.Errorf("create onnx session: %w", err)
			return
		}
		d.session = session
		log.Printf("[velar] onnx-ner: model loaded from %s (labels: %d)", d.cfg.ModelDir, len(d.labels))
	})
	return d.loadErr
}

func loadLabels(path string) (map[int]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	parsed := map[string]string{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	labels := make(map[int]string, len(parsed))
	for k, v := range parsed {
		idx, err := strconv.Atoi(k)
		if err != nil {
			return nil, fmt.Errorf("invalid label key %q: %w", k, err)
		}
		labels[idx] = v
	}
	return labels, nil
}

func (d *ONNXNERDetector) Detect(ctx context.Context, text string) ([]Entity, error) {
	if len(text) == 0 || len(text) > d.cfg.MaxBytes {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := d.init(); err != nil {
		return nil, err
	}
	encoded, err := d.tokenizer.Encode(text)
	if err != nil {
		return nil, err
	}
	labels, scores, err := d.runInference(ctx, encoded)
	if err != nil {
		return nil, err
	}
	words := make([]Token, 0, len(labels))
	for i := range labels {
		if i+1 >= len(encoded.TokenToWordIdx) {
			break
		}
		wi := encoded.TokenToWordIdx[i+1]
		if wi < 0 || wi >= len(encoded.Words) {
			continue
		}
		words = append(words, encoded.Words[wi])
	}
	return tokensToEntities(words, labels, scores), nil
}

func (d *ONNXNERDetector) runInference(ctx context.Context, encoded *TokenizerOutput) ([]string, []float64, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}
	if d.session == nil {
		return nil, nil, fmt.Errorf("%w: session unavailable", ErrNERUnavailable)
	}
	rows, err := d.session.Run(ctx, encoded.InputIDs, encoded.AttentionMask, encoded.TokenTypeIDs)
	if err != nil {
		log.Printf("[velar] onnx-ner: inference error: %v, falling back", err)
		return nil, nil, err
	}
	if len(rows) != len(encoded.InputIDs) {
		return nil, nil, fmt.Errorf("unexpected logits rows: got %d want %d", len(rows), len(encoded.InputIDs))
	}
	labels := make([]string, 0, len(rows)-2)
	scores := make([]float64, 0, len(rows)-2)
	for i := 1; i < len(rows)-1; i++ {
		probs := softmax(rows[i])
		bestIdx := 0
		best := -1.0
		for j, p := range probs {
			if p > best {
				best = p
				bestIdx = j
			}
		}
		label := d.labels[bestIdx]
		if label == "" {
			label = "O"
		}
		labels = append(labels, label)
		scores = append(scores, best)
	}
	return labels, scores, nil
}

func softmax(logits []float32) []float64 {
	if len(logits) == 0 {
		return nil
	}
	maxV := logits[0]
	for _, v := range logits[1:] {
		if v > maxV {
			maxV = v
		}
	}
	probs := make([]float64, len(logits))
	sum := 0.0
	for i, v := range logits {
		e := math.Exp(float64(v - maxV))
		probs[i] = e
		sum += e
	}
	if sum == 0 {
		uniform := 1.0 / float64(len(logits))
		for i := range probs {
			probs[i] = uniform
		}
		return probs
	}
	for i := range probs {
		probs[i] /= sum
	}
	return probs
}

func labelKeys(m map[int]string) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
