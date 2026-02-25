package models

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Progress struct {
	Downloaded int64
	Total      int64
	SpeedMBps  float64
	ETA        time.Duration
}

type ProgressCallback func(Progress)

type Downloader struct {
	Client    *http.Client
	Retries   int
	RetryWait time.Duration

	mu sync.Mutex
}

func NewDownloader() *Downloader {
	return &Downloader{
		Client:    &http.Client{Timeout: 0},
		Retries:   2,
		RetryWait: 500 * time.Millisecond,
	}
}

func (d *Downloader) DownloadAndInstall(ctx context.Context, model ModelSpec, modelsRoot string, onProgress ProgressCallback) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := os.MkdirAll(modelsRoot, 0o755); err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp(modelsRoot, model.Name+"-download-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	extractDir := filepath.Join(tmpDir, "extract")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return err
	}

	downloadPath := filepath.Join(tmpDir, "download.bin")
	if err := d.downloadWithRetry(ctx, model.URL, downloadPath, onProgress); err != nil {
		return err
	}
	if err := VerifyChecksum(downloadPath, model.Checksum); err != nil {
		return err
	}

	isGzip, err := isGzipFile(downloadPath)
	if err != nil {
		return err
	}
	if isGzip {
		if err := ExtractTarGz(downloadPath, extractDir); err != nil {
			return err
		}
	} else {
		// Direct ONNX download: move model file and fetch auxiliary files
		if err := os.Rename(downloadPath, filepath.Join(extractDir, "model.onnx")); err != nil {
			return err
		}

		// Download tokenizer.json
		if model.TokenizerURL == "" {
			return fmt.Errorf("tokenizer_url required for ONNX model %q", model.Name)
		}
		tokPath := filepath.Join(extractDir, "tokenizer.json")
		if err := d.downloadWithRetry(ctx, model.TokenizerURL, tokPath, nil); err != nil {
			return fmt.Errorf("download tokenizer: %w", err)
		}

		// Download and convert config.json to labels.json
		if model.ConfigURL == "" {
			return fmt.Errorf("config_url required for ONNX model %q", model.Name)
		}
		configPath := filepath.Join(tmpDir, "config.json")
		if err := d.downloadWithRetry(ctx, model.ConfigURL, configPath, nil); err != nil {
			return fmt.Errorf("download config: %w", err)
		}
		labelsData, err := extractLabelsFromConfig(configPath)
		if err != nil {
			return fmt.Errorf("extract labels from config: %w", err)
		}
		if err := os.WriteFile(filepath.Join(extractDir, "labels.json"), labelsData, 0o644); err != nil {
			return err
		}
	}

	if err := ValidateModelDir(extractDir); err != nil {
		return err
	}

	finalPath := ModelInstallPath(modelsRoot, model.Name)
	oldPath := finalPath + ".bak"
	_ = os.RemoveAll(oldPath)
	if _, err := os.Stat(finalPath); err == nil {
		if err := os.Rename(finalPath, oldPath); err != nil {
			return err
		}
	}
	if err := os.Rename(extractDir, finalPath); err != nil {
		_ = os.Rename(oldPath, finalPath)
		return err
	}
	if err := os.WriteFile(filepath.Join(finalPath, ".checksum"), []byte(model.Checksum+"\n"), 0o644); err != nil {
		return err
	}
	_ = os.RemoveAll(oldPath)
	return nil
}

func (d *Downloader) downloadWithRetry(ctx context.Context, url, dest string, onProgress ProgressCallback) error {
	var lastErr error
	for attempt := 0; attempt <= d.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d.RetryWait):
			}
		}
		lastErr = d.download(ctx, url, dest, onProgress)
		if lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("download failed after retries: %w", lastErr)
}

func (d *Downloader) download(ctx context.Context, url, dest string, onProgress ProgressCallback) error {
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download status %d", resp.StatusCode)
	}
	buf := make([]byte, 32*1024)
	start := time.Now()
	var downloaded int64
	total := resp.ContentLength
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
			downloaded += int64(n)
			if onProgress != nil {
				elapsed := time.Since(start).Seconds()
				speed := 0.0
				if elapsed > 0 {
					speed = float64(downloaded) / elapsed / 1024 / 1024
				}
				eta := time.Duration(0)
				if total > 0 && speed > 0 {
					remainingMB := float64(total-downloaded) / 1024 / 1024
					eta = time.Duration(remainingMB / speed * float64(time.Second))
				}
				onProgress(Progress{Downloaded: downloaded, Total: total, SpeedMBps: speed, ETA: eta})
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func VerifyChecksum(file, expected string) error {
	if strings.TrimSpace(expected) == "" {
		return fmt.Errorf("checksum missing")
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actual := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if actual != expected {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

func ExtractTarGz(archivePath, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(hdr.Name)
		clean = strings.TrimPrefix(clean, "./")
		if clean == "." || strings.HasPrefix(clean, "../") {
			continue
		}
		target := filepath.Join(dest, clean)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}

func ValidateModelDir(base string) error {
	candidates := []string{base}
	entries, _ := os.ReadDir(base)
	for _, e := range entries {
		if e.IsDir() {
			candidates = append(candidates, filepath.Join(base, e.Name()))
		}
	}
	for _, c := range candidates {
		required := []string{"model.onnx", "labels.json", "tokenizer.json"}
		ok := true
		for _, file := range required {
			if _, err := os.Stat(filepath.Join(c, file)); err != nil {
				ok = false
				break
			}
		}
		if ok {
			if c != base {
				for _, file := range required {
					if err := os.Rename(filepath.Join(c, file), filepath.Join(base, file)); err != nil {
						return err
					}
				}
			}
			return nil
		}
	}
	return fmt.Errorf("invalid model archive: missing required files")
}

func isGzipFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var hdr [2]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false, err
	}
	return hdr[0] == 0x1f && hdr[1] == 0x8b, nil
}

func extractLabelsFromConfig(configPath string) ([]byte, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		ID2Label map[string]string `json:"id2label"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.ID2Label) == 0 {
		return nil, fmt.Errorf("id2label not found in config")
	}
	return json.Marshal(cfg.ID2Label)
}
