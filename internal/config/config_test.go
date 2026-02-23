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

func TestParseYAMLLiteONNXNERConfig(t *testing.T) {
	cfg := Default()
	err := parseYAMLLite(strings.NewReader(`sanitizer:
  detectors:
    onnx_ner:
      enabled: true
      max_bytes: 4096
      timeout_ms: 25
      min_score: 0.8
`), &cfg)
	if err != nil {
		t.Fatalf("parseYAMLLite() error = %v", err)
	}
	ner := cfg.Sanitizer.Detectors.ONNXNER
	if !ner.Enabled || ner.MaxBytes != 4096 || ner.TimeoutMS != 25 || ner.MinScore != 0.8 {
		t.Fatalf("unexpected onnx_ner config: %+v", ner)
	}
}
