package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"velar/internal/audit"
	"velar/internal/classifier"
	"velar/internal/config"
	"velar/internal/policy"
	"velar/internal/proxy"
	"velar/internal/stats"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("velard failed: %v", err)
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

	startedAt := time.Now().UTC()
	engine := policy.NewRuleEngine(cfg.Rules)
	cls := classifier.HostClassifier{}
	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	server := proxy.New(addr, engine, cls, auditLogger, cfg.MITM, cfg.Sanitizer, cfg.Notifications)
	statsServer := newStatsServer(cfg, startedAt)

	errCh := make(chan error, 2)
	go func() { errCh <- server.Start() }()
	go func() {
		err := statsServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received signal %s, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := statsServer.Shutdown(ctx); err != nil {
			return err
		}
		return server.Shutdown(ctx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func newStatsServer(cfg config.Config, startedAt time.Time) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		entries, err := audit.ParseFile(cfg.LogFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		st := stats.CollectFromEntries(entries, stats.Options{
			Now:    time.Now().UTC(),
			Status: "running",
			Uptime: time.Since(startedAt),
			Port:   cfg.Port,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(st)
	})
	return &http.Server{Addr: "127.0.0.1:8081", Handler: mux}
}
