package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultPort    = 8080
	defaultLogFile = "~/.promptshield/audit.log"
)

type Match struct {
	Host         string `json:"host"`
	HostContains string `json:"host_contains"`
}

type Rule struct {
	ID     string `json:"id"`
	Match  Match  `json:"match"`
	Action string `json:"action"`
}

type Config struct {
	Port          int           `json:"port"`
	LogFile       string        `json:"log_file"`
	MITM          MITM          `json:"mitm"`
	Sanitizer     Sanitizer     `json:"sanitizer"`
	Notifications Notifications `json:"notifications"`
	Rules         []Rule        `json:"rules"`
}

type MITM struct {
	Enabled bool     `json:"enabled"`
	Domains []string `json:"domains"`
}

type Sanitizer struct {
	Enabled             bool     `json:"enabled"`
	Types               []string `json:"types"`
	ConfidenceThreshold float64  `json:"confidence_threshold"`
	MaxReplacements     int      `json:"max_replacements"`
}

type Notifications struct {
	Enabled bool `json:"enabled"`
}

func Default() Config {
	return Config{
		Port:          defaultPort,
		LogFile:       defaultLogFile,
		MITM:          MITM{},
		Sanitizer:     Sanitizer{Types: []string{"email", "phone", "api_key", "jwt"}},
		Notifications: Notifications{Enabled: true},
		Rules: []Rule{{
			ID:     "allow_all",
			Action: "allow",
		}},
	}
}

func ConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".promptshield", "config.yaml"), nil
}

func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg.LogFile = expandHome(cfg.LogFile)
			return cfg, nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	if err := parseConfig(data, &cfg); err != nil {
		return Config{}, err
	}

	cfg.LogFile = expandHome(cfg.LogFile)
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.LogFile == "" {
		cfg.LogFile = expandHome(defaultLogFile)
	}
	if len(cfg.Rules) == 0 {
		cfg.Rules = Default().Rules
	}

	return cfg, nil
}

func EnsureConfigDir(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0o755)
}

func parseConfig(data []byte, cfg *Config) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, cfg); err != nil {
			return fmt.Errorf("parse json config: %w", err)
		}
		return nil
	}
	return parseYAMLLite(strings.NewReader(trimmed), cfg)
}

func parseYAMLLite(r *strings.Reader, cfg *Config) error {
	s := bufio.NewScanner(r)
	var currentRule *Rule
	inMatch := false
	inMITM := false
	inMITMDomains := false
	inSanitizer := false
	inSanitizerTypes := false
	inNotifications := false
	rulesFound := false

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimLeft(line, "-")
		line = strings.TrimSpace(line)

		switch {
		case line == "rules:":
			if !rulesFound {
				cfg.Rules = nil
				rulesFound = true
			}
			inSanitizer = false
			inSanitizerTypes = false
			inMITMDomains = false
			inMITM = false
			inNotifications = false
			continue
		case line == "mitm:":
			inSanitizer = false
			inSanitizerTypes = false
			inMITM = true
			inMITMDomains = false
			inNotifications = false
			continue
		case line == "sanitizer:":
			inMITM = false
			inMITMDomains = false
			inSanitizer = true
			inSanitizerTypes = false
			inNotifications = false
			continue
		case line == "notifications:":
			inMITM = false
			inMITMDomains = false
			inSanitizer = false
			inSanitizerTypes = false
			inNotifications = true
			continue
		case line == "domains:" && inMITM:
			inMITMDomains = true
			continue
		case line == "types:" && inSanitizer:
			cfg.Sanitizer.Types = nil
			inSanitizerTypes = true
			continue
		case inMITMDomains && strings.HasPrefix(strings.TrimSpace(s.Text()), "-"):
			domain := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(s.Text()), "-"))
			if domain != "" {
				cfg.MITM.Domains = append(cfg.MITM.Domains, domain)
			}
			continue
		case inSanitizerTypes && strings.HasPrefix(strings.TrimSpace(s.Text()), "-"):
			typ := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(s.Text()), "-"))
			if typ != "" {
				cfg.Sanitizer.Types = append(cfg.Sanitizer.Types, typ)
			}
			continue
		case strings.HasPrefix(line, "port:"):
			inMITMDomains = false
			inSanitizerTypes = false
			v := strings.TrimSpace(strings.TrimPrefix(line, "port:"))
			port, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("invalid port: %s", v)
			}
			cfg.Port = port
		case strings.HasPrefix(line, "log_file:"):
			inMITMDomains = false
			inSanitizerTypes = false
			cfg.LogFile = strings.TrimSpace(strings.TrimPrefix(line, "log_file:"))
		case strings.HasPrefix(line, "enabled:") && inMITM:
			inMITMDomains = false
			cfg.MITM.Enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "enabled:")), "true")
		case strings.HasPrefix(line, "enabled:") && inSanitizer:
			cfg.Sanitizer.Enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "enabled:")), "true")
		case strings.HasPrefix(line, "enabled:") && inNotifications:
			cfg.Notifications.Enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "enabled:")), "true")
		case strings.HasPrefix(line, "confidence_threshold:") && inSanitizer:
			v := strings.TrimSpace(strings.TrimPrefix(line, "confidence_threshold:"))
			threshold, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return fmt.Errorf("invalid confidence_threshold: %s", v)
			}
			cfg.Sanitizer.ConfidenceThreshold = threshold
		case strings.HasPrefix(line, "max_replacements:") && inSanitizer:
			v := strings.TrimSpace(strings.TrimPrefix(line, "max_replacements:"))
			maxRepl, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("invalid max_replacements: %s", v)
			}
			cfg.Sanitizer.MaxReplacements = maxRepl
		case strings.HasPrefix(line, "id:"):
			inMITMDomains = false
			inSanitizer = false
			inSanitizerTypes = false
			inMITM = false
			cfg.Rules = append(cfg.Rules, Rule{})
			currentRule = &cfg.Rules[len(cfg.Rules)-1]
			currentRule.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			inMatch = false
		case strings.HasPrefix(line, "action:"):
			if currentRule == nil {
				cfg.Rules = append(cfg.Rules, Rule{})
				currentRule = &cfg.Rules[len(cfg.Rules)-1]
			}
			currentRule.Action = strings.TrimSpace(strings.TrimPrefix(line, "action:"))
		case line == "match:":
			inMatch = true
		case strings.HasPrefix(line, "host_contains:") && inMatch && currentRule != nil:
			currentRule.Match.HostContains = strings.TrimSpace(strings.TrimPrefix(line, "host_contains:"))
		case strings.HasPrefix(line, "host:") && inMatch && currentRule != nil:
			currentRule.Match.Host = strings.TrimSpace(strings.TrimPrefix(line, "host:"))
		}
	}

	if err := s.Err(); err != nil {
		return fmt.Errorf("scan config: %w", err)
	}
	return nil
}

func expandHome(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}
