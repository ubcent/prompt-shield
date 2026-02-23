package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"velar/internal/audit"
	"velar/internal/classifier"
	"velar/internal/config"
	"velar/internal/policy"
	"velar/internal/proxy"
	"velar/internal/proxy/mitm"
	"velar/internal/systemproxy"
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
	case "stop":
		err = stopDaemon()
	case "restart":
		err = restartDaemon()
	case "status":
		err = status()
	case "logs":
		err = logs()
	case "ca":
		err = ca(flag.Args()[1:])
	case "proxy":
		err = proxyCommand(flag.Args()[1:])
	case "daemon":
		err = runDaemon()
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		log.Fatalf("velar %s failed: %v", cmd, err)
	}
}

func usage() {
	fmt.Println("Usage: velar [start|stop|restart|status|logs|ca init|ca print|proxy on|proxy off|proxy status]")
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

func runDaemon() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	auditLogger, err := audit.NewJSONLLogger(cfg.LogFile)
	if err != nil {
		return err
	}

	engine := policy.NewRuleEngine(cfg.Rules)
	cls := classifier.HostClassifier{}
	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	server := proxy.New(addr, engine, cls, auditLogger, cfg.MITM, cfg.Sanitizer, cfg.Notifications)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received signal %s, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
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
		fmt.Printf("Velar already running (pid=%d)\n", pid)
		return nil
	}

	if runtime.GOOS == "darwin" && isSystemProxyEnabled(cfg.Port) && !isDaemonRunning() {
		fmt.Println("Detected stale proxy settings. Disabling system proxy.")
		if err := disableSystemProxy(); err != nil {
			return err
		}
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
		_ = cmd.Process.Kill()
		return err
	}

	fmt.Printf("Velar started (pid=%d)\n", cmd.Process.Pid)
	fmt.Printf("Proxy: http://localhost:%d\n", cfg.Port)
	fmt.Printf("MITM: %s\n", enabledLabel(cfg.MITM.Enabled))
	fmt.Printf("Sanitizer: %s\n", enabledLabel(cfg.Sanitizer.Enabled))
	fmt.Printf("Config: %s\n", mustConfigPath())
	fmt.Printf("Daemon log: %s\n", stdoutLog)
	fmt.Printf("Log file: %s\n", cfg.LogFile)
	return nil
}

func stopDaemon() error {
	if runtime.GOOS == "darwin" {
		if err := disableSystemProxy(); err != nil {
			return err
		}
	}

	pid, err := readPID()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("Velar not running")
			return nil
		}
		return err
	}

	if !isProcessRunning(pid) {
		_ = os.Remove(pidFilePath())
		fmt.Println("Velar not running")
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !isProcessRunning(pid) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if isProcessRunning(pid) {
		if err := proc.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
	}

	if err := os.Remove(pidFilePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Printf("Velar stopped (pid=%d)\n", pid)
	return nil
}

func restartDaemon() error {
	if err := stopDaemon(); err != nil {
		return err
	}
	return startDaemon()
}

func status() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	running, pid := processStatus()
	if !running {
		fmt.Println("Status: stopped")
	} else {
		fmt.Println("Status: running")
		fmt.Printf("PID: %d\n", pid)
	}
	fmt.Printf("Port: %d\n", cfg.Port)
	fmt.Printf("MITM: %s\n", enabledLabel(cfg.MITM.Enabled))
	fmt.Printf("Sanitizer: %s\n", enabledLabel(cfg.Sanitizer.Enabled))
	fmt.Printf("Log file: %s\n", cfg.LogFile)
	stdoutLog, err := daemonLogPath()
	if err != nil {
		return err
	}
	fmt.Printf("Daemon log: %s\n", stdoutLog)
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
		return fmt.Errorf("usage: velar ca [init|print]")
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
		fmt.Println("macOS install: open ~/.velar/ca/cert.pem")
		fmt.Println("Then add it to Keychain and set Trust to 'Always Trust'.")
		return nil
	default:
		return fmt.Errorf("usage: velar ca [init|print]")
	}
}

func proxyCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: velar proxy [on|off|status]")
	}

	switch args[0] {
	case "on":
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if !isDaemonRunning() {
			fmt.Println("Cannot enable proxy: Velar is not running")
			os.Exit(1)
		}
		if _, err := systemproxy.Enable("localhost", cfg.Port); err != nil {
			return err
		}
		fmt.Printf("System proxy enabled (localhost:%d)\n", cfg.Port)
		return nil
	case "off":
		if _, err := systemproxy.Disable(); err != nil {
			return err
		}
		fmt.Println("System proxy disabled")
		return nil
	case "status":
		st, err := systemproxy.CurrentStatus()
		if err != nil {
			return err
		}
		effective := st.Web
		if st.Secure.Enabled {
			effective = st.Secure
		}
		fmt.Printf("Proxy: %s\n", enabledLabel(effective.Enabled))
		fmt.Printf("Host: %s\n", effective.Host)
		fmt.Printf("Port: %d\n", effective.Port)
		fmt.Printf("Service: %s\n", st.Service)
		return nil
	default:
		return fmt.Errorf("usage: velar proxy [on|off|status]")
	}
}

func daemonCommand() (*exec.Cmd, error) {
	if path, err := exec.LookPath("velard"); err == nil {
		return exec.Command(path), nil
	}
	if _, err := os.Stat(filepath.Join(".", "velard")); err == nil {
		return exec.Command("./velard"), nil
	}
	return exec.Command("go", "run", "./cmd/velard"), nil
}

func isDaemonRunning() bool {
	pid, err := readPID()
	if err != nil {
		return false
	}
	return isProcessRunning(pid)
}

func disableSystemProxy() error {
	if _, err := systemproxy.Disable(); err != nil {
		return err
	}
	fmt.Println("System proxy disabled")
	return nil
}

func isSystemProxyEnabled(port int) bool {
	path, err := exec.LookPath("networksetup")
	if err != nil {
		return false
	}
	out, err := exec.Command(path, "-getwebproxy", "Wi-Fi").CombinedOutput()
	if err != nil {
		return false
	}

	var (
		enabled bool
		host    string
		cfgPort int
	)

	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "Enabled":
			enabled = strings.EqualFold(val, "Yes")
		case "Server":
			host = val
		case "Port":
			cfgPort, _ = strconv.Atoi(val)
		}
	}

	return enabled && host == "localhost" && cfgPort == port
}

func processStatus() (bool, int) {
	pid, err := readPID()
	if err != nil {
		return false, 0
	}
	if !isProcessRunning(pid) {
		_ = os.Remove(pidFilePath())
		return false, 0
	}
	return true, pid
}

func readPID() (int, error) {
	pidData, err := os.ReadFile(pidFilePath())
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid pid file")
	}
	return pid, nil
}

func isProcessRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	return true
}

func pidFilePath() string {
	appDir, err := config.AppDir()
	if err != nil {
		return ".velar/velar.pid"
	}
	return filepath.Join(appDir, "velar.pid")
}

func daemonLogPath() (string, error) {
	appDir, err := config.AppDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(appDir, "daemon.log"), nil
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
		return "~/.velar/config.yaml"
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
