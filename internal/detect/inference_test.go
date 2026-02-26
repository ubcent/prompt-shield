package detect

import (
	"math"
	"testing"
)

func TestSoftmax_SumsToOne(t *testing.T) {
	probs := softmax([]float32{0.2, 0.4, 0.8})
	s := 0.0
	for _, p := range probs {
		s += p
	}
	if s < 0.9999 || s > 1.0001 {
		t.Fatalf("sum=%f", s)
	}
}

func TestSoftmax_MaxIsArgmax(t *testing.T) {
	probs := softmax([]float32{0, 0, 10, 0})
	bestIdx := 0
	best := probs[0]
	for i, p := range probs {
		if p > best {
			best = p
			bestIdx = i
		}
	}
	if bestIdx != 2 {
		t.Fatalf("argmax=%d", bestIdx)
	}
}

func TestSoftmax_NumericalStability(t *testing.T) {
	probs := softmax([]float32{1000, 1001, 1002})
	for _, p := range probs {
		if math.IsNaN(p) || math.IsInf(p, 0) {
			t.Fatalf("bad prob %f", p)
		}
	}
}
