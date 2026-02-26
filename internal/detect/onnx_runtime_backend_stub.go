//go:build !onnxruntime

package detect

func createONNXSession(modelPath string) (nerSession, error) {
	return newPythonONNXSession(modelPath), nil
}
