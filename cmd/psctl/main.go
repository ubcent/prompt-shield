package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"promptshield/internal/audit"
	"promptshield/internal/classifier"
	"promptshield/internal/config"
	"promptshield/internal/policy"
	"promptshield/internal/proxy"
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
	fmt.Println("Usage: psctl [start|status|logs|ca init]")
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
	logger, err := audit.NewJSONLLogger(cfg.LogFile)
	if err != nil {
		return err
	}
	server := proxy.New(fmt.Sprintf("127.0.0.1:%d", cfg.Port), policy.NewRuleEngine(cfg.Rules), classifier.HostClassifier{}, logger, cfg.MITM, cfg.Sanitizer)

	errCh := make(chan error, 1)
	go func() { errCh <- server.Start() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		fmt.Printf("received %s, shutting down\n", sig)
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

func status() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		fmt.Printf("PromptShield is not running on %s\n", addr)
		return nil
	}
	_ = conn.Close()
	fmt.Printf("PromptShield is running on %s\n", addr)
	return nil
}

func logs() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	f, err := os.Open(cfg.LogFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("audit log does not exist yet")
			return nil
		}
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
	return nil
}

func ca(args []string) error {
	if len(args) == 0 || args[0] != "init" {
		return fmt.Errorf("usage: psctl ca init")
	}
	path, err := mitm.DefaultCAPath()
	if err != nil {
		return err
	}
	store := mitm.NewCAStore(path)
	if err := store.EnsureRootCA(); err != nil {
		return err
	}
	fmt.Printf("Root CA ready at %s\n", path)
	return nil
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
