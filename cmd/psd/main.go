package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"promptshield/internal/audit"
	"promptshield/internal/classifier"
	"promptshield/internal/config"
	"promptshield/internal/policy"
	"promptshield/internal/proxy"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("psd failed: %v", err)
	}
}

func run() error {
	cfgPath, err := config.ConfigPath()
	if err != nil {
		return err
	}
	if err := config.EnsureConfigDir(cfgPath); err != nil {
		return err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	auditLogger, err := audit.NewJSONLLogger(cfg.LogFile)
	if err != nil {
		return err
	}

	engine := policy.NewRuleEngine(cfg.Rules)
	cls := classifier.HostClassifier{}
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	server := proxy.New(addr, engine, cls, auditLogger)

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
