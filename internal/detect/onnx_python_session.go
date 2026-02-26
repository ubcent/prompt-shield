package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

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

	cmd := exec.CommandContext(ctx, "python3", "-c", pythonONNXInferScript)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("python onnx inference failed: %v: %s", err, stderr.String())
		}
		return nil, fmt.Errorf("python onnx inference failed: %w", err)
	}

	resp := pythonInferResponse{}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("parse python onnx output: %w", err)
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
