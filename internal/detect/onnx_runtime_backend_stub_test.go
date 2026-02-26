//go:build !onnxruntime

package detect

import "testing"

func TestCreateONNXSession_NativeRequestedWithoutTag(t *testing.T) {
	t.Setenv("VELAR_ONNX_BACKEND", "native")
	_, err := createONNXSession("/tmp/model.onnx")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateONNXSession_DefaultsToPython(t *testing.T) {
	t.Setenv("VELAR_ONNX_BACKEND", "")
	s, err := createONNXSession("/tmp/model.onnx")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*pythonONNXSession); !ok {
		t.Fatalf("expected python session, got %T", s)
	}
}
