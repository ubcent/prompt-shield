package stats

import (
	"sort"
	"strings"
	"time"

	"velar/internal/audit"
)

type Stats struct {
	Status        string           `json:"status"`
	UptimeSeconds int64            `json:"uptime_seconds"`
	Port          int              `json:"port"`
	Requests      RequestStats     `json:"requests"`
	MaskedItems   MaskedItemsStats `json:"masked_items"`
	Latency       LatencyStats     `json:"latency"`
	TopDomains    []DomainStats    `json:"top_domains"`
	Recent        []RecentRequest  `json:"recent,omitempty"`
}

type RequestStats struct {
	Total       int     `json:"total"`
	PerMinute   float64 `json:"per_minute"`
	Last5Minute []int   `json:"last_5_minute"`
}

type MaskedItemsStats struct {
	Total  int            `json:"total"`
	ByType map[string]int `json:"by_type"`
}

type LatencyStats struct {
	SanitizeMs float64 `json:"sanitize_ms"`
	UpstreamMs float64 `json:"upstream_ms"`
	TotalMs    float64 `json:"total_ms"`
}

type DomainStats struct {
	Domain   string `json:"domain"`
	Requests int    `json:"requests"`
}

type RecentRequest struct {
	Timestamp  string         `json:"timestamp"`
	Domain     string         `json:"domain"`
	Method     string         `json:"method"`
	StatusCode int            `json:"status_code"`
	MaskedBy   map[string]int `json:"masked_by"`
	Masked     int            `json:"masked_count"`
	SanitizeMs float64        `json:"sanitize_ms"`
	UpstreamMs float64        `json:"upstream_ms"`
	TotalMs    float64        `json:"total_ms"`
}

type Options struct {
	Now     time.Time
	Status  string
	Uptime  time.Duration
	Port    int
	TopN    int
	RecentN int
}

func CollectFromEntries(entries []audit.Entry, opts Options) Stats {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	topN := opts.TopN
	if topN <= 0 {
		topN = 5
	}
	recentN := opts.RecentN
	if recentN <= 0 {
		recentN = 20
	}

	out := Stats{
		Status:        opts.Status,
		UptimeSeconds: int64(opts.Uptime.Seconds()),
		Port:          opts.Port,
		MaskedItems:   MaskedItemsStats{ByType: map[string]int{}},
		Requests:      RequestStats{Last5Minute: make([]int, 5)},
	}
	if out.Status == "" {
		out.Status = "stopped"
	}

	domains := map[string]int{}
	var sanitizeSum, upstreamSum, totalSum float64
	var sanitizeCount, upstreamCount, totalCount int
	recent := make([]RecentRequest, 0, len(entries))

	for _, e := range entries {
		out.Requests.Total++
		host := strings.TrimSpace(e.Host)
		if host != "" {
			domains[host]++
		}

		maskedBy := map[string]int{}
		for _, item := range e.SanitizedItems {
			t := strings.ToUpper(strings.TrimSpace(item.Type))
			if t == "" {
				continue
			}
			maskedBy[t]++
			out.MaskedItems.ByType[t]++
			out.MaskedItems.Total++
		}

		if !opts.Now.IsZero() && e.Timestamp != "" {
			if ts, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil {
				delta := now.Sub(ts)
				if delta >= 0 && delta < 5*time.Minute {
					idx := int(delta / time.Minute)
					out.Requests.Last5Minute[4-idx]++
				}
			}
		}

		if e.SanitizeLatencyMs > 0 {
			sanitizeSum += e.SanitizeLatencyMs
			sanitizeCount++
		}
		if e.UpstreamLatencyMs > 0 {
			upstreamSum += e.UpstreamLatencyMs
			upstreamCount++
		}
		if e.TotalLatencyMs > 0 {
			totalSum += e.TotalLatencyMs
			totalCount++
		}

		recent = append(recent, RecentRequest{
			Timestamp:  e.Timestamp,
			Domain:     host,
			Method:     e.Method,
			StatusCode: e.StatusCode,
			MaskedBy:   maskedBy,
			Masked:     len(e.SanitizedItems),
			SanitizeMs: e.SanitizeLatencyMs,
			UpstreamMs: e.UpstreamLatencyMs,
			TotalMs:    e.TotalLatencyMs,
		})
	}

	sum5 := 0
	for _, n := range out.Requests.Last5Minute {
		sum5 += n
	}
	out.Requests.PerMinute = float64(sum5) / 5

	if sanitizeCount > 0 {
		out.Latency.SanitizeMs = sanitizeSum / float64(sanitizeCount)
	}
	if upstreamCount > 0 {
		out.Latency.UpstreamMs = upstreamSum / float64(upstreamCount)
	}
	if totalCount > 0 {
		out.Latency.TotalMs = totalSum / float64(totalCount)
	}

	for d, c := range domains {
		out.TopDomains = append(out.TopDomains, DomainStats{Domain: d, Requests: c})
	}
	sort.Slice(out.TopDomains, func(i, j int) bool {
		if out.TopDomains[i].Requests == out.TopDomains[j].Requests {
			return out.TopDomains[i].Domain < out.TopDomains[j].Domain
		}
		return out.TopDomains[i].Requests > out.TopDomains[j].Requests
	})
	if len(out.TopDomains) > topN {
		out.TopDomains = out.TopDomains[:topN]
	}

	for i := len(recent) - 1; i >= 0 && len(out.Recent) < recentN; i-- {
		out.Recent = append(out.Recent, recent[i])
	}
	return out
}
