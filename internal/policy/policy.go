package policy

import (
	"fmt"
	"strings"

	"promptshield/internal/config"
)

type Decision string

const (
	Allow Decision = "allow"
	Block Decision = "block"
)

type Result struct {
	Decision Decision
	Reason   string
	RuleID   string
}

type Engine interface {
	Evaluate(host string) Result
}

type RuleEngine struct {
	rules []config.Rule
}

func NewRuleEngine(rules []config.Rule) *RuleEngine {
	return &RuleEngine{rules: rules}
}

func (e *RuleEngine) Evaluate(host string) Result {
	host = strings.ToLower(host)
	for _, r := range e.rules {
		if !matches(host, r.Match) {
			continue
		}
		action := strings.ToLower(r.Action)
		switch action {
		case string(Block):
			return Result{Decision: Block, Reason: "matched rule", RuleID: ruleID(r.ID)}
		case string(Allow):
			return Result{Decision: Allow, Reason: "matched rule", RuleID: ruleID(r.ID)}
		default:
			return Result{Decision: Block, Reason: fmt.Sprintf("invalid action %q", r.Action), RuleID: ruleID(r.ID)}
		}
	}

	return Result{Decision: Allow, Reason: "default allow", RuleID: "default"}
}

func matches(host string, m config.Match) bool {
	if m.Host == "" && m.HostContains == "" {
		return true
	}
	if m.Host != "" && strings.EqualFold(m.Host, host) {
		return true
	}
	if m.HostContains != "" && strings.Contains(host, strings.ToLower(m.HostContains)) {
		return true
	}
	return false
}

func ruleID(id string) string {
	if id == "" {
		return "unnamed"
	}
	return id
}
