package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
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

var renderStatsFunc = renderStats

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
	return watchStatsLoop(recent, export, ticker.C, sigCh)
}

func watchStatsLoop(recent bool, export string, ticks <-chan time.Time, stop <-chan os.Signal) error {
	for {
		if err := renderStatsFunc(recent, export); err != nil {
			return err
		}
		fmt.Print("\033[H\033[2J")
		select {
		case <-ticks:
		case <-stop:
			return nil
		}
	}
}

func renderStats(recent bool, export string) error {
	st, err := getStats()
	if err != nil {
		return err
	}
	switch strings.ToLower(export) {
	case "":
		if recent {
			printRecent(st)
			return nil
		}
		printSummary(st)
		return nil
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	case "csv":
		if !recent {
			return fmt.Errorf("csv export requires --recent")
		}
		return exportRecentCSV(st.Recent)
	default:
		return fmt.Errorf("unsupported export format %q", export)
	}
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

func printSummary(st stats.Stats) {
	fmt.Println("Velar Statistics")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Status:      %s\n", st.Status)
	fmt.Printf("Uptime:      %s\n", time.Duration(st.UptimeSeconds)*time.Second)
	fmt.Printf("Port:        %d\n", st.Port)
	fmt.Printf("Requests:    %d (%.1f/min last 5m)\n", st.Requests.Total, st.Requests.PerMinute)
	fmt.Printf("Latency avg: sanitize %.1fms | upstream %.1fms | total %.1fms\n", st.Latency.SanitizeMs, st.Latency.UpstreamMs, st.Latency.TotalMs)
	fmt.Println()
	fmt.Println("Masked Items")
	fmt.Println(strings.Repeat("-", 40))
	types := make([]string, 0, len(st.MaskedItems.ByType))
	for k := range st.MaskedItems.ByType {
		types = append(types, k)
	}
	sort.Strings(types)
	for _, t := range types {
		v := st.MaskedItems.ByType[t]
		fmt.Printf("%-12s %5d %s\n", t+":", v, progress(v, st.MaskedItems.Total))
	}
	fmt.Printf("Total:       %d\n\n", st.MaskedItems.Total)

	fmt.Println("Top Domains")
	fmt.Println(strings.Repeat("-", 40))
	for _, d := range st.TopDomains {
		fmt.Printf("%-24s %d\n", d.Domain, d.Requests)
	}
}

func printRecent(st stats.Stats) {
	fmt.Println("Recent Requests (last 20)")
	fmt.Println(strings.Repeat("-", 90))
	fmt.Printf("%-10s %-24s %-6s %-6s %-20s %-8s\n", "TIME", "DOMAIN", "METHOD", "STATUS", "MASKED", "LATENCY")
	fmt.Println(strings.Repeat("-", 90))
	for _, r := range st.Recent {
		tm := r.Timestamp
		if ts, err := time.Parse(time.RFC3339Nano, r.Timestamp); err == nil {
			tm = ts.Format("15:04:05")
		}
		fmt.Printf("%-10s %-24s %-6s %-6d %-20s %-8.1fms\n", tm, r.Domain, r.Method, r.StatusCode, maskedLabel(r.MaskedBy), r.TotalMs)
	}
	fmt.Println(strings.Repeat("-", 90))
	fmt.Printf("Showing %d of %d total requests\n", len(st.Recent), st.Requests.Total)
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

func exportRecentCSV(rows []stats.RecentRequest) error {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()
	if err := w.Write([]string{"timestamp", "domain", "method", "status", "masked_types", "masked_count", "latency_ms"}); err != nil {
		return err
	}
	for _, r := range rows {
		types := make([]string, 0, len(r.MaskedBy))
		for t := range r.MaskedBy {
			types = append(types, t)
		}
		sort.Strings(types)
		if err := w.Write([]string{
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
	return w.Error()
}
