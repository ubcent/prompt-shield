//go:build darwin

package systemproxy

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const networksetupBin = "networksetup"

func Enable(host string, port int) (string, error) {
	service, err := activeService()
	if err != nil {
		return "", err
	}

	status, err := statusForService(service)
	if err != nil {
		return "", err
	}
	if err := saveBackup(Backup{Service: service, Web: status.Web, Secure: status.Secure}); err != nil {
		return "", err
	}

	if err := runNetworksetup("-setwebproxy", service, host, fmt.Sprintf("%d", port)); err != nil {
		return "", err
	}
	if err := runNetworksetup("-setsecurewebproxy", service, host, fmt.Sprintf("%d", port)); err != nil {
		return "", err
	}
	if err := runNetworksetup("-setwebproxystate", service, "on"); err != nil {
		return "", err
	}
	if err := runNetworksetup("-setsecurewebproxystate", service, "on"); err != nil {
		return "", err
	}
	return service, nil
}

func Disable() (string, error) {
	backup, ok, err := loadBackup()
	if err != nil {
		return "", err
	}
	if ok {
		if backup.Service == "" {
			return "", errors.New("invalid proxy backup: missing service")
		}
		if err := restoreProxy(backup.Service, backup.Web, false); err != nil {
			return "", err
		}
		if err := restoreProxy(backup.Service, backup.Secure, true); err != nil {
			return "", err
		}
		if err := deleteBackup(); err != nil {
			return "", err
		}
		return backup.Service, nil
	}

	service, err := activeService()
	if err != nil {
		return "", err
	}
	if err := runNetworksetup("-setwebproxystate", service, "off"); err != nil {
		return "", err
	}
	if err := runNetworksetup("-setsecurewebproxystate", service, "off"); err != nil {
		return "", err
	}
	return service, nil
}

func CurrentStatus() (Status, error) {
	service, err := activeService()
	if err != nil {
		return Status{}, err
	}
	return statusForService(service)
}

func statusForService(service string) (Status, error) {
	webOut, err := runNetworksetupOutput("-getwebproxy", service)
	if err != nil {
		return Status{}, err
	}
	secureOut, err := runNetworksetupOutput("-getsecurewebproxy", service)
	if err != nil {
		return Status{}, err
	}
	webCfg, err := parseProxyConfig(webOut)
	if err != nil {
		return Status{}, err
	}
	secureCfg, err := parseProxyConfig(secureOut)
	if err != nil {
		return Status{}, err
	}
	return Status{Service: service, Web: webCfg, Secure: secureCfg}, nil
}

func activeService() (string, error) {
	out, err := runNetworksetupOutput("-listallnetworkservices")
	if err != nil {
		return "", err
	}
	services := parseNetworkServices(out)
	if len(services) == 0 {
		return "", errors.New("no network services found")
	}
	return choosePreferredService(services), nil
}

func restoreProxy(service string, cfg ProxyConfig, secure bool) error {
	setCmd := "-setwebproxy"
	stateCmd := "-setwebproxystate"
	if secure {
		setCmd = "-setsecurewebproxy"
		stateCmd = "-setsecurewebproxystate"
	}
	if cfg.Host != "" && cfg.Port > 0 {
		if err := runNetworksetup(setCmd, service, cfg.Host, fmt.Sprintf("%d", cfg.Port)); err != nil {
			return err
		}
	}
	state := "off"
	if cfg.Enabled {
		state = "on"
	}
	return runNetworksetup(stateCmd, service, state)
}

func runNetworksetup(args ...string) error {
	_, err := runNetworksetupOutput(args...)
	return err
}

func runNetworksetupOutput(args ...string) (string, error) {
	path, err := exec.LookPath(networksetupBin)
	if err != nil {
		return "", fmt.Errorf("networksetup not found in PATH")
	}
	cmd := exec.Command(path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(strings.ToLower(msg), "not authorized") || strings.Contains(strings.ToLower(msg), "permission") {
			return "", fmt.Errorf("permission denied while changing system proxy settings: %s", msg)
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("networksetup %s failed: %s", strings.Join(args, " "), msg)
	}
	return string(out), nil
}
