package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"velar/internal/detect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: velar test-ner <text>")
		fmt.Println("Example: velar test-ner \"My name is Jane Doe and I work at Acme Corp\"")
		os.Exit(1)
	}

	text := os.Args[1]

	log.SetFlags(0)

	fmt.Println("=== ONNX NER Test ===")
	fmt.Printf("Text: %q\n\n", text)

	// Create detector with default config
	cfg := detect.ONNXNERConfig{
		MaxBytes: 32 * 1024,
		MinScore: 0.70,
	}

	detector := detect.NewONNXNERDetector(cfg)

	// Run detection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	entities, err := detector.Detect(ctx, text)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("\nTroubleshooting:")
		fmt.Println("- Ensure Python dependencies are installed: pip3 install onnxruntime numpy")
		fmt.Println("- Download the model: velar model download ner_en")
		fmt.Println("- See docs/onnx-ner-troubleshooting.md for more help")
		os.Exit(1)
	}

	fmt.Printf("OK: detection completed in %v\n", duration)
	fmt.Printf("Found %d entities:\n\n", len(entities))

	if len(entities) == 0 {
		fmt.Println("WARN: no entities detected")
		fmt.Println("\nThis could mean:")
		fmt.Println("- The text doesn't contain person names, organizations, or locations")
		fmt.Println("- The confidence scores are below the threshold (0.70)")
		fmt.Println("- The model doesn't recognize the entities in this text")
	} else {
		// Print as table
		fmt.Printf("%-5s %-12s %-30s %-6s %-6s %-8s\n", "#", "Type", "Text", "Start", "End", "Score")
		fmt.Println("───────────────────────────────────────────────────────────────────────────")
		for i, e := range entities {
			extractedText := text[e.Start:e.End]
			if len(extractedText) > 28 {
				extractedText = extractedText[:25] + "..."
			}
			fmt.Printf("%-5d %-12s %-30s %-6d %-6d %.2f\n",
				i+1, e.Type, extractedText, e.Start, e.End, e.Score)
		}

		// Also output as JSON for programmatic use
		fmt.Println("\nJSON Output:")
		jsonData, _ := json.MarshalIndent(entities, "", "  ")
		fmt.Println(string(jsonData))
	}
}
