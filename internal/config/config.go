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
	Port    int    `json:"port"`
	LogFile string `json:"log_file"`
	Rules   []Rule `json:"rules"`
}

func Default() Config {
	return Config{
		Port:    defaultPort,
		LogFile: defaultLogFile,
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

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimLeft(line, "-")
		line = strings.TrimSpace(line)

		switch {
		case line == "rules:":
			continue
		case strings.HasPrefix(line, "port:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "port:"))
			port, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("invalid port: %s", v)
			}
			cfg.Port = port
		case strings.HasPrefix(line, "log_file:"):
			cfg.LogFile = strings.TrimSpace(strings.TrimPrefix(line, "log_file:"))
		case strings.HasPrefix(line, "id:"):
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
