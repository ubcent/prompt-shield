package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"velar/internal/audit"
	"velar/internal/stats"
)

const statsAPIURL = "http://127.0.0.1:8081/api/stats"

var renderStatsTextFunc = renderStatsText

func statsCommand(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	watch := fs.Bool("watch", false, "watch stats")
	recent := fs.Bool("recent", false, "show recent requests")
	export := fs.String("export", "", "export format: json|csv")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *watch {
		return watchStats(*recent, *export)
	}
	return renderStats(*recent, *export)
}

func watchStats(recent bool, export string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	if export == "" && isTerminal() {
		hideCursor()
		defer showCursor()
	}
	return watchStatsLoop(recent, export, ticker.C, sigCh)
}

func watchStatsLoop(recent bool, export string, ticks <-chan time.Time, stop <-chan os.Signal) error {
	for {
		out, err := renderStatsTextFunc(recent, export)
		if err != nil {
			return err
		}
		if export == "" && isTerminal() {
			clearScreen()
		}
		fmt.Fprint(os.Stdout, out)
		select {
		case <-ticks:
		case <-stop:
			return nil
		}
	}
}

func renderStatsText(recent bool, export string) (string, error) {
	var buf strings.Builder
	if err := renderStatsTo(&buf, recent, export); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func renderStats(recent bool, export string) error {
	return renderStatsTo(os.Stdout, recent, export)
}

func renderStatsTo(w io.Writer, recent bool, export string) error {
	st, err := getStats()
	if err != nil {
		return err
	}
	switch strings.ToLower(export) {
	case "":
		if recent {
			printRecent(w, st)
			return nil
		}
		printSummary(w, st)
		return nil
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	case "csv":
		if !recent {
			return fmt.Errorf("csv export requires --recent")
		}
		return exportRecentCSV(w, st.Recent)
	default:
		return fmt.Errorf("unsupported export format %q", export)
	}
}

func clearScreen() {
	fmt.Fprint(os.Stdout, "\033[H\033[2J\033[3J")
}

func hideCursor() {
	fmt.Fprint(os.Stdout, "\033[?25l")
}

func showCursor() {
	fmt.Fprint(os.Stdout, "\033[?25h")
}

func isTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func getStats() (stats.Stats, error) {
	if st, err := fetchDaemonStats(); err == nil {
		return st, nil
	}

	cfg, err := loadConfig()
	if err != nil {
		return stats.Stats{}, err
	}
	entries, err := audit.ParseFile(cfg.LogFile)
	if err != nil {
		return stats.Stats{}, err
	}
	running, _ := processStatus()
	status := "stopped"
	if running {
		status = "running"
	}
	return stats.CollectFromEntries(entries, stats.Options{Now: time.Now().UTC(), Status: status, Port: cfg.Port}), nil
}

func fetchDaemonStats() (stats.Stats, error) {
	client := &http.Client{Timeout: 700 * time.Millisecond}
	resp, err := client.Get(statsAPIURL)
	if err != nil {
		return stats.Stats{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return stats.Stats{}, fmt.Errorf("stats API status %d", resp.StatusCode)
	}
	var st stats.Stats
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return stats.Stats{}, err
	}
	return st, nil
}

func printSummary(w io.Writer, st stats.Stats) {
	fmt.Fprintln(w, "Velar Statistics")
	fmt.Fprintln(w, strings.Repeat("-", 40))
	fmt.Fprintf(w, "Status:      %s\n", st.Status)
	fmt.Fprintf(w, "Uptime:      %s\n", time.Duration(st.UptimeSeconds)*time.Second)
	fmt.Fprintf(w, "Port:        %d\n", st.Port)
	fmt.Fprintf(w, "Requests:    %d (%.1f/min last 5m)\n", st.Requests.Total, st.Requests.PerMinute)
	fmt.Fprintf(w, "Latency avg: sanitize %.1fms | upstream %.1fms | total %.1fms\n", st.Latency.SanitizeMs, st.Latency.UpstreamMs, st.Latency.TotalMs)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Masked Items")
	fmt.Fprintln(w, strings.Repeat("-", 40))
	types := make([]string, 0, len(st.MaskedItems.ByType))
	for k := range st.MaskedItems.ByType {
		types = append(types, k)
	}
	sort.Strings(types)
	for _, t := range types {
		v := st.MaskedItems.ByType[t]
		fmt.Fprintf(w, "%-12s %5d %s\n", t+":", v, progress(v, st.MaskedItems.Total))
	}
	fmt.Fprintf(w, "Total:       %d\n\n", st.MaskedItems.Total)

	fmt.Fprintln(w, "Top Domains")
	fmt.Fprintln(w, strings.Repeat("-", 40))
	for _, d := range st.TopDomains {
		fmt.Fprintf(w, "%-24s %d\n", d.Domain, d.Requests)
	}
}

func printRecent(w io.Writer, st stats.Stats) {
	fmt.Fprintln(w, "Recent Requests (last 20)")
	fmt.Fprintln(w, strings.Repeat("-", 90))
	fmt.Fprintf(w, "%-10s %-24s %-6s %-6s %-20s %-8s\n", "TIME", "DOMAIN", "METHOD", "STATUS", "MASKED", "LATENCY")
	fmt.Fprintln(w, strings.Repeat("-", 90))
	for _, r := range st.Recent {
		tm := r.Timestamp
		if ts, err := time.Parse(time.RFC3339Nano, r.Timestamp); err == nil {
			tm = ts.Format("15:04:05")
		}
		fmt.Fprintf(w, "%-10s %-24s %-6s %-6d %-20s %-8.1fms\n", tm, r.Domain, r.Method, r.StatusCode, maskedLabel(r.MaskedBy), r.TotalMs)
	}
	fmt.Fprintln(w, strings.Repeat("-", 90))
	fmt.Fprintf(w, "Showing %d of %d total requests\n", len(st.Recent), st.Requests.Total)
}

func progress(v, total int) string {
	if total <= 0 {
		return ""
	}
	p := int(float64(v) / float64(total) * 20)
	if p > 20 {
		p = 20
	}
	return strings.Repeat("█", p) + strings.Repeat("░", 20-p)
}

func maskedLabel(masked map[string]int) string {
	if len(masked) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(masked))
	for t, c := range masked {
		parts = append(parts, fmt.Sprintf("%d %s", c, t))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func exportRecentCSV(w io.Writer, rows []stats.RecentRequest) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{"timestamp", "domain", "method", "status", "masked_types", "masked_count", "latency_ms"}); err != nil {
		return err
	}
	for _, r := range rows {
		types := make([]string, 0, len(r.MaskedBy))
		for t := range r.MaskedBy {
			types = append(types, t)
		}
		sort.Strings(types)
		if err := cw.Write([]string{
			r.Timestamp,
			r.Domain,
			r.Method,
			fmt.Sprintf("%d", r.StatusCode),
			strings.Join(types, "|"),
			fmt.Sprintf("%d", r.Masked),
			fmt.Sprintf("%.3f", r.TotalMs),
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}
