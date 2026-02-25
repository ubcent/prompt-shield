package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"velar/internal/models"
)

func TestHumanBytes(t *testing.T) {
	if got := humanBytes(50 * 1024 * 1024); got != "50 MB" {
		t.Fatalf("unexpected: %s", got)
	}
}

func TestModelListAndInfo(t *testing.T) {
	reg := models.Registry{Models: []models.ModelSpec{{Name: "ner_en", Language: "en", SizeBytes: 50 * 1024 * 1024, EntityTypes: []string{"PERSON"}, Description: "desc", URL: "http://example", Version: "1.0.0"}}}
	root := t.TempDir()

	out := captureStdout(t, func() {
		if err := modelList(reg, root); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "ner_en") || !strings.Contains(out, "not installed") {
		t.Fatalf("unexpected list output: %s", out)
	}

	info := captureStdout(t, func() {
		if err := modelInfo(reg, root, "ner_en"); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(info, "NER Model: ner_en") {
		t.Fatalf("unexpected info output: %s", info)
	}
}

func TestModelVerifyDetectsInvalid(t *testing.T) {
	reg := models.Registry{Models: []models.ModelSpec{{Name: "ner_en", Checksum: "sha256:x"}}}
	root := t.TempDir()
	dir := filepath.Join(root, "ner_en")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "model.onnx"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "labels.json"), []byte("not-json"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "tokenizer.json"), []byte("{}"), 0o644)

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	verifyErr := modelVerify(reg, root)
	_ = w.Close()
	os.Stdout = old
	if verifyErr == nil {
		t.Fatal("expected verification error")
	}
	var b bytes.Buffer
	_, _ = b.ReadFrom(r)
	out := b.String()
	if !strings.Contains(out, "Loadable... ✗") {
		t.Fatalf("expected invalid loadable message: %s", out)
	}
}

func TestModelVerifyDetectsInvalidTokenizer(t *testing.T) {
	reg := models.Registry{Models: []models.ModelSpec{{Name: "ner_en", Checksum: "sha256:x"}}}
	root := t.TempDir()
	dir := filepath.Join(root, "ner_en")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "model.onnx"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "labels.json"), []byte("{\"0\":\"O\"}"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "tokenizer.json"), []byte("not-json"), 0o644)

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	verifyErr := modelVerify(reg, root)
	_ = w.Close()
	os.Stdout = old
	if verifyErr == nil {
		t.Fatal("expected verification error")
	}
	var b bytes.Buffer
	_, _ = b.ReadFrom(r)
	out := b.String()
	if !strings.Contains(out, "tokenizer.json") {
		t.Fatalf("expected tokenizer error in output: %s", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()
	_ = w.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(r)
	return b.String()
}
