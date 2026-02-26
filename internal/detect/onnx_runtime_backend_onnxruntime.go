//go:build onnxruntime

package detect

import (
	"fmt"

	_ "github.com/yalue/onnxruntime_go"
)

func createONNXSession(_ string) (nerSession, error) {
	return nil, fmt.Errorf("onnxruntime backend selected but session wiring is not implemented yet")
}
