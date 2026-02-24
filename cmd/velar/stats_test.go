package main

import (
	"bytes"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"velar/internal/stats"
)

func TestExportRecentCSV(t *testing.T) {
	rows := []stats.RecentRequest{{Timestamp: "2024-01-01T00:00:00Z", Domain: "api.openai.com", Method: "POST", StatusCode: 200, MaskedBy: map[string]int{"EMAIL": 2}, Masked: 2, TotalMs: 123.4}}
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	if err := exportRecentCSV(rows); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	os.Stdout = old
	var b bytes.Buffer
	_, _ = b.ReadFrom(r)
	out := b.String()
	if !strings.Contains(out, "timestamp,domain,method,status") {
		t.Fatalf("missing csv header: %s", out)
	}
}

func TestWatchStatsLoopCancellation(t *testing.T) {
	old := renderStatsFunc
	renderStatsFunc = func(bool, string) error { return nil }
	defer func() { renderStatsFunc = old }()
	ticks := make(chan time.Time, 1)
	stop := make(chan os.Signal, 1)
	stop <- syscall.SIGTERM
	if err := watchStatsLoop(false, "", ticks, stop); err != nil {
		t.Fatal(err)
	}
}
