package models

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

//go:embed registry.json
var embeddedRegistry []byte

type Registry struct {
	Version string      `json:"version"`
	Models  []ModelSpec `json:"models"`
}

type Accuracy struct {
	F1Score   float64 `json:"f1_score"`
	Benchmark string  `json:"benchmark"`
}

type Requirements struct {
	MinMemoryMB int    `json:"min_memory_mb"`
	ONNXVersion string `json:"onnx_version"`
}

type ModelSpec struct {
	Name         string       `json:"name"`
	DisplayName  string       `json:"display_name"`
	Version      string       `json:"version"`
	Language     string       `json:"language"`
	URL          string       `json:"url"`
	Checksum     string       `json:"checksum"`
	SizeBytes    int64        `json:"size_bytes"`
	EntityTypes  []string     `json:"entity_types"`
	Description  string       `json:"description"`
	Architecture string       `json:"architecture"`
	Accuracy     Accuracy     `json:"accuracy"`
	Requirements Requirements `json:"requirements"`
	License      string       `json:"license"`
	Recommended  bool         `json:"recommended"`
}

func LoadEmbeddedRegistry() (Registry, error) {
	return parseRegistry(embeddedRegistry)
}

func parseRegistry(data []byte) (Registry, error) {
	var reg Registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return Registry{}, fmt.Errorf("parse model registry: %w", err)
	}
	sort.Slice(reg.Models, func(i, j int) bool { return reg.Models[i].Name < reg.Models[j].Name })
	return reg, nil
}

func (r Registry) Find(name string) (ModelSpec, bool) {
	for _, m := range r.Models {
		if m.Name == name {
			return m, true
		}
	}
	return ModelSpec{}, false
}

func DefaultModelsRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".velar", "models"), nil
}

func ModelInstallPath(root string, name string) string {
	return filepath.Join(root, name)
}

func IsInstalled(root string, model ModelSpec) bool {
	base := ModelInstallPath(root, model.Name)
	required := []string{"model.onnx", "labels.json", "tokenizer.json"}
	for _, f := range required {
		if _, err := os.Stat(filepath.Join(base, f)); err != nil {
			return false
		}
	}
	return true
}
