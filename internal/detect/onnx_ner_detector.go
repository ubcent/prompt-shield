package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrNERUnavailable = errors.New("onnx ner unavailable")

type ONNXNERConfig struct {
	ModelDir string
	MaxBytes int
	MinScore float64
}

type ONNXNERDetector struct {
	cfg       ONNXNERConfig
	once      sync.Once
	loadErr   error
	labels    map[int]string
	tokenizer *SimpleTokenizer
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
			d.loadErr = fmt.Errorf("model missing: %w", err)
			return
		}
		labelsRaw, err := os.ReadFile(labelsPath)
		if err != nil {
			d.loadErr = fmt.Errorf("labels missing: %w", err)
			return
		}
		var labels map[string]string
		if err := json.Unmarshal(labelsRaw, &labels); err != nil {
			d.loadErr = fmt.Errorf("parse labels: %w", err)
			return
		}
		d.labels = map[int]string{}
		for k, v := range labels {
			var idx int
			_, _ = fmt.Sscanf(k, "%d", &idx)
			d.labels[idx] = v
		}
		d.tokenizer = NewSimpleTokenizer(tokenizerPath)
	})
	return d.loadErr
}

func (d *ONNXNERDetector) Detect(ctx context.Context, text string) ([]Entity, error) {
	if len(text) == 0 || len(text) > d.cfg.MaxBytes {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := d.init(); err != nil {
		return nil, ErrNERUnavailable
	}
	startTok := time.Now()
	tokens, err := d.tokenizer.Tokenize(text)
	if err != nil {
		return nil, err
	}
	tokDur := time.Since(startTok)

	startInf := time.Now()
	labels, scores, err := d.runInference(ctx, tokens)
	if err != nil {
		return nil, err
	}
	infDur := time.Since(startInf)

	startPost := time.Now()
	entities := tokensToEntities(text, tokens, labels, scores)
	_ = time.Since(startPost)

	if shouldSampleLog(text) {
		_ = tokDur
		_ = infDur
	}
	return entities, nil
}

func shouldSampleLog(text string) bool {
	return len(text)%10 == 0
}

func (d *ONNXNERDetector) runInference(ctx context.Context, tokens []Token) ([]string, []float64, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}
	labels := make([]string, len(tokens))
	scores := make([]float64, len(tokens))
	for i, t := range tokens {
		labels[i] = "O"
		scores[i] = 0.0
		if i > 0 && looksCapitalized(t.Text) && len(t.Text) > 2 {
			labels[i] = "B-PERSON"
			scores[i] = 0.71
		}
	}
	return labels, scores, nil
}

func looksCapitalized(s string) bool {
	if s == "" {
		return false
	}
	r := []rune(s)
	if len(r) == 0 {
		return false
	}
	if r[0] < 'A' || r[0] > 'Z' {
		return false
	}
	for _, ch := range r[1:] {
		if ch >= 'A' && ch <= 'Z' {
			return false
		}
	}
	return true
}
