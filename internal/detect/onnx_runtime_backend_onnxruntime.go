//go:build onnxruntime

package detect

import (
	"fmt"
	"os"
	"strings"

	_ "github.com/yalue/onnxruntime_go"
)

func createONNXSession(modelPath string) (nerSession, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("VELAR_ONNX_BACKEND")))
	if backend == "" || backend == "native" {
		return nil, fmt.Errorf("native ONNX backend selected but native session wiring is not implemented yet; set VELAR_ONNX_BACKEND=python to use python runtime")
	}
	if backend != "python" {
		return nil, fmt.Errorf("unsupported VELAR_ONNX_BACKEND=%q (expected native or python)", backend)
	}
	return newPythonONNXSession(modelPath), nil
}
