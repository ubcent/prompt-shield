//go:build !onnxruntime

package detect

import "fmt"

func createONNXSession(_ string) (nerSession, error) {
	return nil, fmt.Errorf("onnx runtime backend is not wired in this build (rebuild with -tags onnxruntime)")
}
