package classifier

import "testing"

func TestHostClassifierClassify(t *testing.T) {
	c := HostClassifier{}
	tests := []struct {
		host string
		want Category
	}{
		{host: "api.openai.com", want: LLMOpenAI},
		{host: "console.anthropic.com", want: LLMAnthropic},
		{host: "unknown.com", want: Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := c.Classify(tt.host); got != tt.want {
				t.Fatalf("Classify(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
