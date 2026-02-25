package models

import _ "embed"

var (
	//go:embed ner_en/labels.json
	nerEnLabels []byte
	//go:embed ner_en/tokenizer.json
	nerEnTokenizer []byte
)

func EmbeddedAuxFiles(modelName string) (labels []byte, tokenizer []byte, ok bool) {
	switch modelName {
	case "ner_en":
		return nerEnLabels, nerEnTokenizer, true
	default:
		return nil, nil, false
	}
}
