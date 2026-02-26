//go:build !onnxruntime

package detect

import (
	"fmt"
	"os"
	"strings"
)

func createONNXSession(modelPath string) (nerSession, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("VELAR_ONNX_BACKEND")))
	if backend == "native" {
		return nil, fmt.Errorf("native ONNX backend requires build tag 'onnxruntime'")
	}
	return newPythonONNXSession(modelPath), nil
}
