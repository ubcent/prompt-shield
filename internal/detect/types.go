package detect

import "context"

type Entity struct {
	Type   string
	Start  int
	End    int
	Score  float64
	Source string
}

type Detector interface {
	Detect(ctx context.Context, text string) ([]Entity, error)
}
