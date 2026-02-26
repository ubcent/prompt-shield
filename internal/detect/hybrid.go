package detect

import (
	"context"
	"log"
	"sort"
	"time"
	"unicode"
)

type HybridConfig struct {
	NerEnabled bool
	MaxBytes   int
	Timeout    time.Duration
	MinScore   float64
}

type NERStatus struct {
	Enabled   bool
	Available bool
	LastError error
}

type HybridDetector struct {
	Fast   []Detector
	Ner    Detector
	Config HybridConfig
}

func (h HybridDetector) Detect(ctx context.Context, text string) ([]Entity, error) {
	all := make([]Entity, 0)
	for _, d := range h.Fast {
		entities, err := d.Detect(ctx, text)
		if err != nil {
			continue
		}
		all = append(all, entities...)
	}
	if h.Config.NerEnabled && h.Ner != nil && shouldRunNER(text) {
		if h.Config.MaxBytes <= 0 || len(text) <= h.Config.MaxBytes {
			nerCtx := ctx
			cancel := func() {}
			if h.Config.Timeout > 0 {
				nerCtx, cancel = context.WithTimeout(ctx, h.Config.Timeout)
			}
			entities, err := h.Ner.Detect(nerCtx, text)
			cancel()
			if err == nil {
				filteredCount := 0
				for _, e := range entities {
					if e.Score >= h.Config.MinScore {
						all = append(all, e)
						filteredCount++
					}
				}
				if len(entities) > 0 && filteredCount == 0 {
					log.Printf("[velar] onnx-ner: detected %d entities but all filtered out by min_score=%.2f (consider lowering threshold)", len(entities), h.Config.MinScore)
				}
			} else if err == ErrNERUnavailable {
				// Don't log every time - init already logged the issue
			} else if err == context.DeadlineExceeded {
				log.Printf("[velar] onnx-ner: inference timeout after %s, falling back to regex-only", h.Config.Timeout)
			} else {
				log.Printf("[velar] onnx-ner: inference error: %v, falling back to regex-only", err)
			}
		}
	}
	return mergeEntities(all), nil
}

func (h HybridDetector) NERStatus() NERStatus {
	return NERStatus{Enabled: h.Config.NerEnabled, Available: h.Config.NerEnabled && h.Ner != nil}
}

func shouldRunNER(text string) bool {
	if len(text) < 8 {
		return false
	}
	total := 0.0
	letters := 0.0
	spaces := 0.0
	for _, r := range text {
		total++
		if unicode.IsLetter(r) {
			letters++
		}
		if unicode.IsSpace(r) {
			spaces++
		}
	}
	if total == 0 {
		return false
	}
	// Text should look like natural language: enough letters and spaces.
	// Punctuation is NOT required — user messages and chat prompts often omit it.
	return (letters/total) > 0.4 && (spaces/total) > 0.05
}

func mergeEntities(all []Entity) []Entity {
	if len(all) == 0 {
		return nil
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Start == all[j].Start {
			if all[i].End == all[j].End {
				return all[i].Score > all[j].Score
			}
			return all[i].End > all[j].End
		}
		return all[i].Start < all[j].Start
	})
	chosen := make([]Entity, 0, len(all))
	for _, e := range all {
		if len(chosen) == 0 {
			chosen = append(chosen, e)
			continue
		}
		last := chosen[len(chosen)-1]
		if e.Start < last.End {
			if prefer(e, last) {
				chosen[len(chosen)-1] = e
			}
			continue
		}
		chosen = append(chosen, e)
	}
	return chosen
}

func prefer(a, b Entity) bool {
	if a.Source == "regex" && b.Source != "regex" {
		return true
	}
	if a.Source != "regex" && b.Source == "regex" {
		return false
	}
	return a.Score > b.Score
}
