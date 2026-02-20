package config

import (
	"strings"
	"testing"
)

func TestParseYAMLLiteSanitizerConfig(t *testing.T) {
	cfg := Default()
	err := parseYAMLLite(strings.NewReader(`sanitizer:
  enabled: true
  types:
    - email
    - api_key
  confidence_threshold: 0.7
  max_replacements: 5
`), &cfg)
	if err != nil {
		t.Fatalf("parseYAMLLite() error = %v", err)
	}
	if !cfg.Sanitizer.Enabled || len(cfg.Sanitizer.Types) != 2 || cfg.Sanitizer.Types[1] != "api_key" || cfg.Sanitizer.MaxReplacements != 5 {
		t.Fatalf("unexpected sanitizer config: %+v", cfg.Sanitizer)
	}
}

func TestParseYAMLLiteNotificationsConfig(t *testing.T) {
	cfg := Default()
	err := parseYAMLLite(strings.NewReader(`notifications:
  enabled: false
`), &cfg)
	if err != nil {
		t.Fatalf("parseYAMLLite() error = %v", err)
	}
	if cfg.Notifications.Enabled {
		t.Fatalf("expected notifications to be disabled")
	}
}
