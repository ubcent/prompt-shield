package models

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func buildModelArchive(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	files := map[string]string{
		"ner_en/model.onnx":     "dummy-onnx",
		"ner_en/labels.json":    `{"0":"O","1":"B-PERSON"}`,
		"ner_en/tokenizer.json": `{}`,
	}
	for name, content := range files {
		h := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestDownloadAndInstall(t *testing.T) {
	archive := buildModelArchive(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(archive)))
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	tmp := t.TempDir()
	m := ModelSpec{Name: "ner_en", URL: srv.URL, Checksum: checksum(archive)}
	dl := NewDownloader()
	var calls atomic.Int32
	if err := dl.DownloadAndInstall(context.Background(), m, tmp, func(Progress) { calls.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if calls.Load() == 0 {
		t.Fatalf("expected progress callback")
	}
	if !IsInstalled(tmp, m) {
		t.Fatalf("model not installed")
	}
}

func TestChecksumVerificationFailure(t *testing.T) {
	archive := buildModelArchive(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	err := NewDownloader().DownloadAndInstall(context.Background(), ModelSpec{Name: "ner_en", URL: srv.URL, Checksum: "sha256:deadbeef"}, t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected checksum error")
	}
}

func TestSlowNetwork(t *testing.T) {
	archive := buildModelArchive(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < len(archive); i += 128 {
			end := i + 128
			if end > len(archive) {
				end = len(archive)
			}
			_, _ = w.Write(archive[i:end])
			w.(http.Flusher).Flush()
			time.Sleep(2 * time.Millisecond)
		}
	}))
	defer srv.Close()

	var last Progress
	err := NewDownloader().DownloadAndInstall(context.Background(), ModelSpec{Name: "ner_en", URL: srv.URL, Checksum: checksum(archive)}, t.TempDir(), func(p Progress) { last = p })
	if err != nil {
		t.Fatal(err)
	}
	if last.Downloaded == 0 {
		t.Fatal("expected download progress")
	}
}

func TestDiskFullLikeError(t *testing.T) {
	archive := buildModelArchive(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	root := filepath.Join(t.TempDir(), "models-file")
	if err := os.WriteFile(root, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := NewDownloader().DownloadAndInstall(context.Background(), ModelSpec{Name: "ner_en", URL: srv.URL, Checksum: checksum(archive)}, root, nil)
	if err == nil {
		t.Fatal("expected write error")
	}
}

func TestConcurrentDownloadsQueued(t *testing.T) {
	archive := buildModelArchive(t)
	var active atomic.Int32
	var maxActive atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := active.Add(1)
		for {
			m := maxActive.Load()
			if cur <= m || maxActive.CompareAndSwap(m, cur) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write(archive)
		active.Add(-1)
	}))
	defer srv.Close()

	dl := NewDownloader()
	tmp := t.TempDir()
	errCh := make(chan error, 2)
	go func() {
		errCh <- dl.DownloadAndInstall(context.Background(), ModelSpec{Name: "ner_en", URL: srv.URL, Checksum: checksum(archive)}, tmp, nil)
	}()
	go func() {
		errCh <- dl.DownloadAndInstall(context.Background(), ModelSpec{Name: "ner_multi", URL: srv.URL, Checksum: checksum(archive)}, tmp, nil)
	}()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if maxActive.Load() > 1 {
		t.Fatalf("expected queued downloads, max active=%d", maxActive.Load())
	}
}

func TestIntegrationDownloadRealModel(t *testing.T) {
	if os.Getenv("VELAR_RUN_INTEGRATION") == "" {
		t.Skip("set VELAR_RUN_INTEGRATION=1 to run real-model download")
	}
	reg, err := LoadEmbeddedRegistry()
	if err != nil {
		t.Fatal(err)
	}
	m, ok := reg.Find("ner_en")
	if !ok {
		t.Fatal("ner_en not found")
	}
	if strings.Contains(m.Checksum, "REPLACE_WITH_RELEASE_CHECKSUM") {
		t.Skip("registry checksum placeholder must be replaced before integration test")
	}
	if err := NewDownloader().DownloadAndInstall(context.Background(), m, t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
}
