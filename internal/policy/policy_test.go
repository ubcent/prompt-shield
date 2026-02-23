package policy

import (
	"testing"

	"velar/internal/config"
)

func TestRuleEngineEvaluate(t *testing.T) {
	tests := []struct {
		name     string
		rules    []config.Rule
		host     string
		decision Decision
		ruleID   string
	}{
		{
			name: "allow rule match by exact host",
			rules: []config.Rule{{ID: "allow-openai", Match: config.Match{Host: "api.openai.com"}, Action: "allow"}},
			host: "api.openai.com", decision: Allow, ruleID: "allow-openai",
		},
		{
			name: "block rule match by host contains",
			rules: []config.Rule{{ID: "block-openai", Match: config.Match{HostContains: "openai.com"}, Action: "block"}},
			host: "api.openai.com", decision: Block, ruleID: "block-openai",
		},
		{
			name: "default action is allow",
			rules: []config.Rule{{ID: "only-anthropic", Match: config.Match{HostContains: "anthropic"}, Action: "block"}},
			host: "example.com", decision: Allow, ruleID: "default",
		},
		{
			name: "first matched rule wins",
			rules: []config.Rule{
				{ID: "allow-first", Match: config.Match{HostContains: "openai.com"}, Action: "allow"},
				{ID: "block-second", Match: config.Match{HostContains: "openai.com"}, Action: "block"},
			},
			host: "api.openai.com", decision: Allow, ruleID: "allow-first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewRuleEngine(tt.rules)
			result := engine.Evaluate(tt.host)
			if result.Decision != tt.decision {
				t.Fatalf("decision = %s, want %s", result.Decision, tt.decision)
			}
			if result.RuleID != tt.ruleID {
				t.Fatalf("ruleID = %s, want %s", result.RuleID, tt.ruleID)
			}
		})
	}
}
