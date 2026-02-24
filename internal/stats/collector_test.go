package stats

import (
	"fmt"
	"testing"
	"time"

	"velar/internal/audit"
)

func TestCollectFromEntriesEmpty(t *testing.T) {
	st := CollectFromEntries(nil, Options{Now: time.Now(), Status: "stopped", Port: 8080})
	if st.Requests.Total != 0 || st.MaskedItems.Total != 0 {
		t.Fatalf("unexpected totals: %+v", st)
	}
}

func TestCollectFromEntriesLarge(t *testing.T) {
	now := time.Now().UTC()
	entries := make([]audit.Entry, 0, 1200)
	for i := 0; i < 1200; i++ {
		entries = append(entries, audit.Entry{
			Timestamp:      now.Add(-time.Duration(i%8) * time.Minute).Format(time.RFC3339Nano),
			Host:           fmt.Sprintf("api-%d.example.com", i%7),
			Method:         "POST",
			StatusCode:     200,
			TotalLatencyMs: 100,
			SanitizedItems: []audit.SanitizedAudit{{Type: "email"}},
		})
	}
	st := CollectFromEntries(entries, Options{Now: now, Status: "running", Port: 8080})
	if st.Requests.Total != 1200 {
		t.Fatalf("got total=%d", st.Requests.Total)
	}
	if st.MaskedItems.ByType["EMAIL"] != 1200 {
		t.Fatalf("unexpected masked total: %d", st.MaskedItems.ByType["EMAIL"])
	}
	if len(st.TopDomains) != 5 {
		t.Fatalf("expected top 5 domains, got %d", len(st.TopDomains))
	}
}
