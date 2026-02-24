package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFileEmpty(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "audit.log")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}
