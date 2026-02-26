//go:build onnxruntime

package detect

import (
	_ "github.com/yalue/onnxruntime_go"
)

func createONNXSession(modelPath string) (nerSession, error) {
	return newPythonONNXSession(modelPath), nil
}
