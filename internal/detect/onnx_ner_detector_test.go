package detect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestONNXDetector_ModelNotFound(t *testing.T) {
	d := NewONNXNERDetector(ONNXNERConfig{ModelDir: filepath.Join(t.TempDir(), "missing")})
	_, err := d.Detect(context.Background(), "John Smith lives in Berlin.")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrNERUnavailable) {
		t.Fatalf("expected ErrNERUnavailable, got %v", err)
	}
	if d.loadErr == nil {
		t.Fatal("expected cached load error")
	}
}

func TestONNXDetector_InvalidLabelsJSON(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "model.onnx"), "x")
	mustWrite(t, filepath.Join(dir, "labels.json"), "{")
	mustWrite(t, filepath.Join(dir, "tokenizer.json"), `{"model":{"vocab":{"[UNK]":1,"[CLS]":2,"[SEP]":3}}}`)
	d := NewONNXNERDetector(ONNXNERConfig{ModelDir: dir})
	_, err := d.Detect(context.Background(), "hello world")
	if err == nil || !strings.Contains(err.Error(), "load labels") {
		t.Fatalf("unexpected err %v", err)
	}
}

func TestONNXDetector_InvalidTokenizerJSON(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "model.onnx"), "x")
	mustWrite(t, filepath.Join(dir, "labels.json"), `{"0":"O"}`)
	mustWrite(t, filepath.Join(dir, "tokenizer.json"), "{")
	d := NewONNXNERDetector(ONNXNERConfig{ModelDir: dir})
	_, err := d.Detect(context.Background(), "hello world")
	if err == nil || !strings.Contains(err.Error(), "load tokenizer") {
		t.Fatalf("unexpected err %v", err)
	}
}

func TestONNXDetector_ContextCancellation(t *testing.T) {
	d := NewONNXNERDetector(ONNXNERConfig{ModelDir: filepath.Join(t.TempDir(), "missing")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := d.Detect(ctx, "abc")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled, got %v", err)
	}
}

func TestONNXDetector_TextTooLarge(t *testing.T) {
	d := NewONNXNERDetector(ONNXNERConfig{MaxBytes: 10})
	entities, err := d.Detect(context.Background(), strings.Repeat("a", 50))
	if err != nil {
		t.Fatal(err)
	}
	if len(entities) != 0 {
		t.Fatalf("expected empty")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
