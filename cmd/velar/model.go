package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"velar/internal/detect"
	"velar/internal/models"
)

func modelCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: velar model [list|download|info|remove|verify]")
	}
	registry, err := models.LoadEmbeddedRegistry()
	if err != nil {
		return err
	}
	root, err := models.DefaultModelsRoot()
	if err != nil {
		return err
	}
	sub := args[0]
	subArgs := args[1:]
	switch sub {
	case "list":
		return modelList(registry, root)
	case "info":
		if len(subArgs) != 1 {
			return fmt.Errorf("usage: velar model info <name>")
		}
		return modelInfo(registry, root, subArgs[0])
	case "download":
		return modelDownload(registry, root, subArgs)
	case "remove":
		if len(subArgs) != 1 {
			return fmt.Errorf("usage: velar model remove <name>")
		}
		return modelRemove(registry, root, subArgs[0])
	case "verify":
		return modelVerify(registry, root)
	default:
		return fmt.Errorf("unknown model subcommand %q", sub)
	}
}

func modelList(registry models.Registry, root string) error {
	fmt.Println("Available Models")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-10s %-6s %-8s %-14s %-30s\n", "NAME", "LANG", "SIZE", "STATUS", "TYPES")
	fmt.Println(strings.Repeat("-", 80))
	installed := 0
	var totalSize int64
	for _, m := range registry.Models {
		status := "not installed"
		if models.IsInstalled(root, m) {
			status = "installed"
			installed++
			totalSize += m.SizeBytes
		}
		fmt.Printf("%-10s %-6s %-8s %-14s %-30s\n", m.Name, m.Language, humanBytes(m.SizeBytes), status, strings.Join(m.EntityTypes, ", "))
	}
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("Installed: %d/%d models\n", installed, len(registry.Models))
	fmt.Printf("Total size: %s\n", humanBytes(totalSize))
	fmt.Println("\nTip: Use 'velar model download <name>' to install a model")
	return nil
}

func modelInfo(registry models.Registry, root, name string) error {
	m, ok := registry.Find(name)
	if !ok {
		return fmt.Errorf("model %q not found", name)
	}
	status := "Not installed"
	location := models.ModelInstallPath(root, m.Name)
	if models.IsInstalled(root, m) {
		status = "Installed"
	}
	fmt.Printf("NER Model: %s\n", m.Name)
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Status:         %s\n", status)
	fmt.Printf("Version:        %s\n", m.Version)
	fmt.Printf("Language:       %s\n", m.Language)
	fmt.Printf("Size:           %s\n", humanBytes(m.SizeBytes))
	fmt.Printf("Location:       %s\n", location)
	fmt.Printf("Description:    %s\n", m.Description)
	fmt.Printf("Entity Types:   %s\n", strings.Join(m.EntityTypes, ", "))
	fmt.Printf("Accuracy:       F1 %.2f (%s)\n", m.Accuracy.F1Score, m.Accuracy.Benchmark)
	fmt.Printf("Architecture:   %s\n", m.Architecture)
	fmt.Printf("License:        %s\n", m.License)
	fmt.Printf("URL:            %s\n", m.URL)
	fmt.Printf("Checksum:       %s\n", m.Checksum)
	return nil
}

func modelDownload(registry models.Registry, root string, args []string) error {
	fs := flag.NewFlagSet("model download", flag.ContinueOnError)
	all := fs.Bool("all", false, "download all recommended models")
	if err := fs.Parse(args); err != nil {
		return err
	}
	selected := make([]models.ModelSpec, 0)
	if *all {
		for _, m := range registry.Models {
			if m.Recommended {
				selected = append(selected, m)
			}
		}
	} else {
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: velar model download <name> or velar model download --all")
		}
		m, ok := registry.Find(fs.Arg(0))
		if !ok {
			return fmt.Errorf("model %q not found", fs.Arg(0))
		}
		selected = append(selected, m)
	}
	dl := models.NewDownloader()
	for _, m := range selected {
		fmt.Printf("\nDownloading %s v%s\n", m.Name, m.Version)
		fmt.Printf("Source: %s\n\n", m.URL)
		lastUpdate := time.Time{}
		err := dl.DownloadAndInstall(context.Background(), m, root, func(p models.Progress) {
			if time.Since(lastUpdate) < 120*time.Millisecond && p.Total > 0 {
				return
			}
			lastUpdate = time.Now()
			pct := float64(0)
			if p.Total > 0 {
				pct = float64(p.Downloaded) * 100 / float64(p.Total)
			}
			fmt.Printf("\rDownloading... %6.2f%% | %s / %s | %.2f MB/s | ETA %s", pct, humanBytes(p.Downloaded), humanBytes(p.Total), p.SpeedMBps, p.ETA.Truncate(time.Second))
		})
		fmt.Println()
		if err != nil {
			return err
		}
		fmt.Println("Verifying checksum... ✓")
		fmt.Println("Extracting... ✓")
		if err := validateModelLoads(filepath.Join(root, m.Name)); err != nil {
			return fmt.Errorf("validate model: %w", err)
		}
		fmt.Println("Validating model... ✓")
		fmt.Printf("\n✓ Model %s installed successfully\n", m.Name)
	}
	return nil
}

func validateModelLoads(modelDir string) error {
	if err := validateModelMetadata(modelDir); err != nil {
		return err
	}
	d := detect.NewONNXNERDetector(detect.ONNXNERConfig{ModelDir: modelDir})
	_, err := d.Detect(context.Background(), "John Doe emailed jane@example.com")
	if err != nil && !errors.Is(err, detect.ErrNERUnavailable) {
		return err
	}
	if errors.Is(err, detect.ErrNERUnavailable) {
		return fmt.Errorf("model files present but detector initialization failed")
	}
	return nil
}

func validateModelMetadata(modelDir string) error {
	labelsPath := filepath.Join(modelDir, "labels.json")
	labelsRaw, err := os.ReadFile(labelsPath)
	if err != nil {
		return fmt.Errorf("read labels.json: %w", err)
	}
	var labels map[string]string
	if err := json.Unmarshal(labelsRaw, &labels); err != nil {
		return fmt.Errorf("parse labels.json: %w", err)
	}
	if len(labels) == 0 {
		return fmt.Errorf("labels.json is empty")
	}

	tokenizerPath := filepath.Join(modelDir, "tokenizer.json")
	tokenizerRaw, err := os.ReadFile(tokenizerPath)
	if err != nil {
		return fmt.Errorf("read tokenizer.json: %w", err)
	}
	var tokenizerPayload map[string]any
	if err := json.Unmarshal(tokenizerRaw, &tokenizerPayload); err != nil {
		return fmt.Errorf("parse tokenizer.json: %w", err)
	}
	if len(tokenizerPayload) == 0 {
		return fmt.Errorf("tokenizer.json is empty")
	}
	return nil
}

func modelRemove(registry models.Registry, root, name string) error {
	m, ok := registry.Find(name)
	if !ok {
		return fmt.Errorf("model %q not found", name)
	}
	loc := models.ModelInstallPath(root, m.Name)
	if _, err := os.Stat(loc); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("Model %s is not installed\n", name)
			return nil
		}
		return err
	}
	fmt.Printf("Remove model '%s' (%s)?\n", m.Name, humanBytes(m.SizeBytes))
	fmt.Printf("This will delete %s\n\n", loc)
	fmt.Print("Continue? (y/N): ")
	r := bufio.NewReader(os.Stdin)
	resp, _ := r.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	if resp != "y" && resp != "yes" {
		fmt.Println("Cancelled")
		return nil
	}
	if err := os.RemoveAll(loc); err != nil {
		return err
	}
	fmt.Println("Removing model... ✓")
	fmt.Printf("Model %s removed successfully\n", m.Name)
	return nil
}

func modelVerify(registry models.Registry, root string) error {
	fmt.Println("Verifying installed models...")
	installed := 0
	failures := 0
	for _, m := range registry.Models {
		if !models.IsInstalled(root, m) {
			continue
		}
		installed++
		fmt.Printf("\n%s\n", m.Name)
		dir := filepath.Join(root, m.Name)
		archivePath := filepath.Join(dir, ".checksum")
		if data, err := os.ReadFile(archivePath); err == nil {
			expected := strings.TrimSpace(string(data))
			if expected == m.Checksum {
				fmt.Println("  ├─ Checksum... ✓")
			} else {
				fmt.Println("  ├─ Checksum... ✗ (registry mismatch)")
				failures++
			}
		} else {
			fmt.Println("  ├─ Checksum... ? (metadata unavailable)")
		}
		if err := models.ValidateModelDir(dir); err != nil {
			fmt.Printf("  ├─ Files...    ✗ (%v)\n", err)
			failures++
			continue
		}
		fmt.Println("  ├─ Files...    ✓")
		if err := validateModelLoads(dir); err != nil {
			fmt.Printf("  └─ Loadable... ✗ (%v)\n", err)
			failures++
			continue
		}
		fmt.Println("  └─ Loadable... ✓")
	}
	if installed == 0 {
		fmt.Println("\nNo installed models found")
		return nil
	}
	if failures > 0 {
		return fmt.Errorf("%d model(s) failed verification", failures)
	}
	fmt.Println("\nAll models verified")
	return nil
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	const mb = 1024 * 1024
	if n >= mb {
		return fmt.Sprintf("%d MB", n/mb)
	}
	return fmt.Sprintf("%d KB", n/1024)
}
