package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

var (
	pythonBinOnce   sync.Once
	pythonBinCached string
)

// resolvePythonBin finds a Python interpreter that has numpy and onnxruntime.
// Priority: $PYTHON_BIN env → .venv/bin/python (relative to cwd) →
// ~/.velar/venv/bin/python → python3 on PATH.
func resolvePythonBin() string {
	pythonBinOnce.Do(func() {
		if v := os.Getenv("PYTHON_BIN"); v != "" {
			pythonBinCached = v
			log.Printf("[velar] onnx-ner: using PYTHON_BIN=%s", v)
			return
		}

		candidates := []string{}

		// .venv relative to working directory
		candidates = append(candidates, filepath.Join(".venv", "bin", "python"))

		// ~/.velar/venv
		if home, err := os.UserHomeDir(); err == nil {
			candidates = append(candidates, filepath.Join(home, ".velar", "venv", "bin", "python"))
		}

		// system python3
		candidates = append(candidates, "python3")

		for _, c := range candidates {
			if pythonHasDeps(c) {
				pythonBinCached = c
				log.Printf("[velar] onnx-ner: resolved python: %s", c)
				return
			}
		}

		// last resort fallback
		pythonBinCached = "python3"
		log.Printf("[velar] onnx-ner: WARNING: no python with numpy+onnxruntime found, falling back to python3")
	})
	return pythonBinCached
}

// pythonHasDeps quickly checks whether the given python binary can import numpy and onnxruntime.
func pythonHasDeps(bin string) bool {
	cmd := exec.Command(bin, "-c", "import numpy, onnxruntime")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

type pythonONNXSession struct {
	modelPath string
}

type pythonInferRequest struct {
	ModelPath     string  `json:"model_path"`
	InputIDs      []int64 `json:"input_ids"`
	AttentionMask []int64 `json:"attention_mask"`
	TokenTypeIDs  []int64 `json:"token_type_ids"`
}

type pythonInferResponse struct {
	Logits [][]float32 `json:"logits"`
	Error  string      `json:"error"`
}

func newPythonONNXSession(modelPath string) nerSession {
	return &pythonONNXSession{modelPath: modelPath}
}

func (s *pythonONNXSession) Run(ctx context.Context, inputIDs, attentionMask, tokenTypeIDs []int64) ([][]float32, error) {
	payload, err := json.Marshal(pythonInferRequest{
		ModelPath:     s.modelPath,
		InputIDs:      inputIDs,
		AttentionMask: attentionMask,
		TokenTypeIDs:  tokenTypeIDs,
	})
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, resolvePythonBin(), "-c", pythonONNXInferScript)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errMsg := ""
		if stderr.Len() > 0 {
			errMsg = stderr.String()
		}
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("python onnx inference timeout (python may be hanging during import): %w", ctx.Err())
		}
		if errMsg != "" {
			return nil, fmt.Errorf("python onnx inference failed: %v: %s", err, errMsg)
		}
		return nil, fmt.Errorf("python onnx inference failed: %w (hint: ensure 'pip3 install onnxruntime numpy' is run)", err)
	}

	resp := pythonInferResponse{}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("parse python onnx output: %w (stdout: %s)", err, stdout.String())
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("python onnx inference error: %s", resp.Error)
	}
	return resp.Logits, nil
}

const pythonONNXInferScript = `
import json
import sys

try:
    import numpy as np
    import onnxruntime as ort
except Exception as exc:
    print(json.dumps({"error": f"missing python dependencies (onnxruntime, numpy): {exc}"}))
    sys.exit(0)

try:
    req = json.load(sys.stdin)
    sess = ort.InferenceSession(req["model_path"], providers=["CPUExecutionProvider"])
    input_names = [i.name for i in sess.get_inputs()]

    seq_len = len(req["input_ids"])
    input_ids = np.array([req["input_ids"]], dtype=np.int64)
    attention_mask = np.array([req["attention_mask"]], dtype=np.int64)
    token_type_ids = np.array([req["token_type_ids"]], dtype=np.int64)

    feed = {}
    for name in input_names:
        if "input_ids" in name:
            feed[name] = input_ids
        elif "attention_mask" in name:
            feed[name] = attention_mask
        elif "token_type_ids" in name:
            feed[name] = token_type_ids

    # Some exports may omit token_type_ids. Fill any unresolved inputs with zeros.
    for name in input_names:
        if name not in feed:
            feed[name] = np.zeros((1, seq_len), dtype=np.int64)

    outputs = sess.run(None, feed)
    logits = outputs[0][0].astype(np.float32).tolist()
    print(json.dumps({"logits": logits}))
except Exception as exc:
    print(json.dumps({"error": str(exc)}))
`
