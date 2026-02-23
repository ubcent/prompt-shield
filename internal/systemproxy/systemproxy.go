package systemproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"promptshield/internal/config"
)

type ProxyConfig struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

type Status struct {
	Service string
	Web     ProxyConfig
	Secure  ProxyConfig
}

type Backup struct {
	Service string      `json:"service"`
	Web     ProxyConfig `json:"web"`
	Secure  ProxyConfig `json:"secure"`
}

func parseNetworkServices(out string) []string {
	lines := strings.Split(out, "\n")
	services := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services
}

func choosePreferredService(services []string) string {
	if len(services) == 0 {
		return ""
	}
	for _, preferred := range []string{"Wi-Fi", "Ethernet"} {
		for _, svc := range services {
			if svc == preferred {
				return svc
			}
		}
	}
	return services[0]
}

func parseProxyConfig(out string) (ProxyConfig, error) {
	cfg := ProxyConfig{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		switch key {
		case "Enabled":
			cfg.Enabled = strings.EqualFold(value, "Yes")
		case "Server":
			cfg.Host = value
		case "Port":
			if value == "" {
				continue
			}
			port, err := strconv.Atoi(value)
			if err != nil {
				return ProxyConfig{}, fmt.Errorf("invalid proxy port %q", value)
			}
			cfg.Port = port
		}
	}
	return cfg, nil
}

func backupFilePath() (string, error) {
	appDir, err := config.AppDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(appDir, "proxy_backup.json"), nil
}

func saveBackup(backup Backup) error {
	path, err := backupFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

func loadBackup() (Backup, bool, error) {
	path, err := backupFilePath()
	if err != nil {
		return Backup{}, false, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Backup{}, false, nil
		}
		return Backup{}, false, err
	}
	var backup Backup
	if err := json.Unmarshal(body, &backup); err != nil {
		return Backup{}, false, err
	}
	return backup, true, nil
}

func deleteBackup() error {
	path, err := backupFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
