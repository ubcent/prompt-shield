package classifier

import "strings"

type Category string

const (
	Unknown      Category = "UNKNOWN"
	LLMOpenAI    Category = "LLM_OPENAI"
	LLMAnthropic Category = "LLM_ANTHROPIC"
)

type Classifier interface {
	Classify(host string) Category
}

type HostClassifier struct{}

func (HostClassifier) Classify(host string) Category {
	h := strings.ToLower(host)
	switch {
	case strings.Contains(h, "openai.com"):
		return LLMOpenAI
	case strings.Contains(h, "anthropic.com"):
		return LLMAnthropic
	default:
		return Unknown
	}
}
