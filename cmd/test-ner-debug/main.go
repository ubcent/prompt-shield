package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"velar/internal/detect"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Test text
	text := "Do you happen to know who Jamie Allen is?"

	fmt.Println("=== ONNX NER Debug Tool ===\n")

	// 1. Check model files
	fmt.Println("1. Checking model files...")
	modelDir := detectModelDir()
	fmt.Printf("   Model directory: %s\n", modelDir)

	files := []string{"model.onnx", "labels.json", "tokenizer.json"}
	allExist := true
	for _, file := range files {
		path := modelDir + "/" + file
		if stat, err := os.Stat(path); err == nil {
			fmt.Printf("   OK: %s exists (size: %d bytes)\n", file, stat.Size())
		} else {
			fmt.Printf("   ERROR: %s missing: %v\n", file, err)
			allExist = false
		}
	}

	if !allExist {
		fmt.Println("\nWARN: model files missing. Run: velar model download ner_en")
		os.Exit(1)
	}

	// 2. Check labels
	fmt.Println("\n2. Checking labels.json...")
	labelsPath := modelDir + "/labels.json"
	labelsData, err := os.ReadFile(labelsPath)
	if err != nil {
		fmt.Printf("   ERROR: cannot read labels: %v\n", err)
	} else {
		var labels map[string]string
		if err := json.Unmarshal(labelsData, &labels); err != nil {
			fmt.Printf("   ERROR: cannot parse labels: %v\n", err)
		} else {
			fmt.Printf("   OK: labels loaded: %d entries\n", len(labels))
			for k, v := range labels {
				fmt.Printf("      %s: %s\n", k, v)
			}
		}
	}

	// 3. Check Python dependencies
	fmt.Println("\n3. Checking Python ONNX Runtime...")
	checkPythonDeps()

	// 4. Test shouldRunNER
	fmt.Println("\n4. Testing shouldRunNER heuristic...")
	fmt.Printf("   Text: %q\n", text)
	if shouldRunNER(text) {
		fmt.Println("   OK: text passes shouldRunNER check")
	} else {
		fmt.Println("   ERROR: text fails shouldRunNER check (won't use NER)")
		os.Exit(1)
	}

	// 5. Create detector
	fmt.Println("\n5. Creating ONNX NER Detector...")
	cfg := detect.ONNXNERConfig{
		ModelDir: modelDir,
		MaxBytes: 32 * 1024,
		MinScore: 0.70,
	}
	detector := detect.NewONNXNERDetector(cfg)
	fmt.Println("   OK: detector created")

	// 6. Test detection
	fmt.Println("\n6. Running detection...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	entities, err := detector.Detect(ctx, text)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("   ERROR: detection failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   OK: detection completed in %v\n", duration)
	fmt.Printf("   Found %d entities:\n", len(entities))
	if len(entities) == 0 {
		fmt.Println("   WARN: no entities detected")
		fmt.Println("\n   This is the issue - the detector should have found 'Jamie Allen' as a PERSON entity.")
	} else {
		for i, e := range entities {
			fmt.Printf("   [%d] Type: %-10s Text: %-20s Start: %3d End: %3d Score: %.2f Source: %s\n",
				i+1, e.Type, text[e.Start:e.End], e.Start, e.End, e.Score, e.Source)
		}
	}

	// 7. Test HybridDetector
	fmt.Println("\n7. Testing HybridDetector (as used in production)...")
	hybrid := detect.HybridDetector{
		Fast: []detect.Detector{detect.RegexDetector{}},
		Ner:  detector,
		Config: detect.HybridConfig{
			NerEnabled: true,
			MaxBytes:   32 * 1024,
			Timeout:    40 * time.Millisecond,
			MinScore:   0.70,
		},
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	hybridEntities, err := hybrid.Detect(ctx2, text)
	if err != nil {
		fmt.Printf("   ERROR: hybrid detection failed: %v\n", err)
	} else {
		fmt.Printf("   OK: hybrid detection found %d entities\n", len(hybridEntities))
		for i, e := range hybridEntities {
			fmt.Printf("   [%d] Type: %-10s Text: %-20s Score: %.2f Source: %s\n",
				i+1, e.Type, text[e.Start:e.End], e.Score, e.Source)
		}
	}

	fmt.Println("\n=== End of Debug ===")
}

func detectModelDir() string {
	home, _ := os.UserHomeDir()
	return home + "/.velar/models/ner_en"
}

func shouldRunNER(text string) bool {
	// Copy of the logic from hybrid.go
	if len(text) < 8 {
		return false
	}
	total := 0.0
	letters := 0.0
	spaces := 0.0
	for _, r := range text {
		total++
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			letters++
		}
		if r == ' ' {
			spaces++
		}
	}
	if total == 0 {
		return false
	}
	return (letters/total) > 0.4 && (spaces/total) > 0.05
}

func checkPythonDeps() {
	cmd := "python3 -c \"import onnxruntime, numpy; print('OK')\""
	result := runCommand(cmd)
	if result == "OK\n" {
		fmt.Println("   OK: Python onnxruntime and numpy installed")
	} else {
		fmt.Println("   ERROR: Python onnxruntime or numpy NOT installed")
		fmt.Println("   Install with: pip3 install onnxruntime numpy")
	}
}

func runCommand(cmd string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if err := c.Run(); err != nil {
		return out.String()
	}
	return out.String()
}
