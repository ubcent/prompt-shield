package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"promptshield/internal/audit"
	"promptshield/internal/config"
	"promptshield/internal/proxy/mitm"
)

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	var err error
	switch cmd {
	case "start":
		err = startDaemon()
	case "status":
		err = status()
	case "logs":
		err = logs()
	case "ca":
		err = ca(flag.Args()[1:])
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		log.Fatalf("psctl %s failed: %v", cmd, err)
	}
}

func usage() {
	fmt.Println("Usage: psctl [start|status|logs|ca init|ca print]")
}

func loadConfig() (config.Config, error) {
	cfgPath, err := config.ConfigPath()
	if err != nil {
		return config.Config{}, err
	}
	if err := config.EnsureConfigDir(cfgPath); err != nil {
		return config.Config{}, err
	}
	return config.Load(cfgPath)
}

func startDaemon() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if _, err := audit.NewJSONLLogger(cfg.LogFile); err != nil {
		return err
	}

	running, pid := processStatus()
	if running {
		fmt.Printf("PromptShield is already running (pid %d)\n", pid)
		return nil
	}

	stdoutLog, err := daemonLogPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(stdoutLog), 0o755); err != nil {
		return err
	}
	lf, err := os.OpenFile(stdoutLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer lf.Close()

	cmd, err := daemonCommand()
	if err != nil {
		return err
	}
	cmd.Stdout = lf
	cmd.Stderr = lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := os.WriteFile(pidFilePath(), []byte(fmt.Sprintf("%d\n", cmd.Process.Pid)), 0o644); err != nil {
		return err
	}

	fmt.Println("PromptShield started")
	fmt.Printf("Proxy: http://localhost:%d\n", cfg.Port)
	fmt.Printf("MITM: %s\n", enabledLabel(cfg.MITM.Enabled))
	fmt.Printf("Sanitizer: %s\n", enabledLabel(cfg.Sanitizer.Enabled))
	fmt.Printf("Config: %s\n", mustConfigPath())
	fmt.Printf("Log file: %s\n", cfg.LogFile)
	return nil
}

func status() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	running, pid := processStatus()
	if !running {
		fmt.Println("PromptShield is not running")
	} else {
		fmt.Printf("PromptShield is running (pid %d)\n", pid)
	}
	fmt.Printf("Port: %d\n", cfg.Port)
	fmt.Printf("MITM: %s\n", enabledLabel(cfg.MITM.Enabled))
	fmt.Printf("Sanitizer: %s\n", enabledLabel(cfg.Sanitizer.Enabled))
	return nil
}

func logs() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_RDONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	lines, err := readLastLines(f, 20)
	if err != nil {
		return err
	}
	for _, line := range lines {
		fmt.Println(line)
	}

	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	for {
		time.Sleep(500 * time.Millisecond)
		stat, err := os.Stat(cfg.LogFile)
		if err != nil {
			return err
		}
		if stat.Size() < offset {
			offset = 0
		}
		if stat.Size() == offset {
			continue
		}
		nf, err := os.Open(cfg.LogFile)
		if err != nil {
			return err
		}
		if _, err := nf.Seek(offset, io.SeekStart); err != nil {
			_ = nf.Close()
			return err
		}
		s := bufio.NewScanner(nf)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line != "" {
				fmt.Println(line)
			}
		}
		if err := s.Err(); err != nil {
			_ = nf.Close()
			return err
		}
		offset = stat.Size()
		_ = nf.Close()
	}
}

func ca(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: psctl ca [init|print]")
	}
	path, err := mitm.DefaultCAPath()
	if err != nil {
		return err
	}

	switch args[0] {
	case "init":
		store := mitm.NewCAStore(path)
		if err := store.EnsureRootCA(); err != nil {
			return err
		}
		fmt.Printf("Root CA ready at %s\n", path)
		fmt.Printf("Certificate: %s\n", filepath.Join(path, "cert.pem"))
		return nil
	case "print":
		certPath := filepath.Join(path, "cert.pem")
		fmt.Printf("Root CA certificate: %s\n", certPath)
		fmt.Println("macOS install: open ~/.promptshield/ca/cert.pem")
		fmt.Println("Then add it to Keychain and set Trust to 'Always Trust'.")
		return nil
	default:
		return fmt.Errorf("usage: psctl ca [init|print]")
	}
}

func daemonCommand() (*exec.Cmd, error) {
	if path, err := exec.LookPath("psd"); err == nil {
		return exec.Command(path), nil
	}
	if _, err := os.Stat(filepath.Join(".", "psd")); err == nil {
		return exec.Command("./psd"), nil
	}
	return exec.Command("go", "run", "./cmd/psd"), nil
}

func processStatus() (bool, int) {
	pidData, err := os.ReadFile(pidFilePath())
	if err != nil {
		return false, 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil || pid <= 0 {
		return false, 0
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, 0
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false, 0
	}
	return true, pid
}

func pidFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".promptshield/psd.pid"
	}
	return filepath.Join(home, ".promptshield", "psd.pid")
}

func daemonLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".promptshield", "psd.log"), nil
}

func enabledLabel(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

func mustConfigPath() string {
	p, err := config.ConfigPath()
	if err != nil {
		return "~/.promptshield/config.yaml"
	}
	return p
}

func readLastLines(r io.Reader, n int) ([]string, error) {
	s := bufio.NewScanner(r)
	buf := make([]string, 0, n)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		buf = append(buf, line)
		if len(buf) > n {
			buf = buf[1:]
		}
	}
	return buf, s.Err()
}
