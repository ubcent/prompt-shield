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
	var b bytes.Buffer
	if err := exportRecentCSV(&b, rows); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "timestamp,domain,method,status") {
		t.Fatalf("missing csv header: %s", out)
	}
}

func TestWatchStatsLoopCancellation(t *testing.T) {
	old := renderStatsTextFunc
	renderStatsTextFunc = func(bool, string) (string, error) { return "", nil }
	defer func() { renderStatsTextFunc = old }()
	ticks := make(chan time.Time, 1)
	stop := make(chan os.Signal, 1)
	stop <- syscall.SIGTERM
	if err := watchStatsLoop(false, "", ticks, stop); err != nil {
		t.Fatal(err)
	}
}
