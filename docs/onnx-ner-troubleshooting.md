# ONNX NER Troubleshooting Guide

## Problem: ONNX NER Not Detecting Entities

### Symptoms
- Model files are downloaded (`~/.velar/models/ner_en/`)
- Config has `onnx_ner.enabled: true`
- But person names, organizations, and locations are not being detected
- Only regex-based detections (email, phone, etc.) work

### Root Causes

The ONNX NER detector requires **Python 3 with onnxruntime** to be installed. The Go code calls Python as a subprocess to run inference.

#### Architecture:
```
Go Code → Python subprocess → onnxruntime → ONNX model → predictions
```

### Diagnostic Steps

#### 1. Check if Python dependencies are installed:

```bash
python3 -c "import onnxruntime, numpy; print('✅ Dependencies OK')"
```

If you use a virtual environment, run the check with that interpreter:

```bash
.venv/bin/python -c "import onnxruntime, numpy; print('✅ Dependencies OK')"
```

**If this hangs or errors**, you need to install the dependencies.

#### 2. Check model files:

```bash
ls -la ~/.velar/models/ner_en/
```

Should show:
- `model.onnx` (large file, ~400MB)
- `labels.json` 
- `tokenizer.json`

#### 3. Check configuration:

```bash
cat ~/.velar/config.yaml | grep -A 5 "onnx_ner"
```

Should show:
```yaml
onnx_ner:
  enabled: true
  max_bytes: 32768
  timeout_ms: 5000
  min_score: 0.70
```

#### 4. Test ONNX inference manually:

```bash
# Create a test script
cat > /tmp/test_onnx.py << 'EOF'
import json
import sys
import numpy as np

try:
    import onnxruntime as ort
    print(f"✅ onnxruntime version: {ort.__version__}")
    print(f"✅ numpy version: {np.__version__}")
    
    # Try to load the model
    model_path = "/Users/$USER/.velar/models/ner_en/model.onnx"
    sess = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
    print(f"✅ Model loaded successfully")
    print(f"   Inputs: {[i.name for i in sess.get_inputs()]}")
    print(f"   Outputs: {[o.name for i in sess.get_outputs()]}")
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
EOF

python3 /tmp/test_onnx.py
```

### Solutions

#### Solution 1: Install Python Dependencies

**Using pip:**
```bash
pip3 install onnxruntime numpy
```

**Using a virtual environment (recommended on macOS Homebrew Python):**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install onnxruntime numpy
```

#### Solution 2: Use a specific Python version

If you have multiple Python installations, you may need to specify which one:

```bash
# Find your Python
which python3

# Install for that specific Python
/usr/local/bin/python3 -m pip install onnxruntime numpy
```

#### Solution 3: Set PYTHON_BIN environment variable (override)

Velar automatically discovers a working Python from `.venv/bin/python`, `~/.velar/venv/bin/python`, or `python3` on PATH. If auto-discovery fails, you can override explicitly:

```bash
export PYTHON_BIN=/path/to/python3
velar start
```

#### Solution 4: Download model again

Sometimes the model download may be incomplete:

```bash
velar model remove ner_en
velar model download ner_en
```

### Verification

After installing dependencies, restart the proxy and test:

```bash
# Restart proxy
velar stop
velar start

# Make a request with a person's name
curl -X POST https://api.example.com/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt": "My name is Jane Doe and I work at Acme Corp"}'

# Check audit log for sanitized entities
tail -1 ~/.velar/audit.log | jq '.sanitized_items'
```

You should see entities like:
```json
[
  {"type": "person", "placeholder": "[PERSON_1]"},
  {"type": "org", "placeholder": "[ORG_1]"}
]
```

### Common Issues

#### Issue: "module 'onnxruntime' has no attribute 'InferenceSession'"

**Cause**: Wrong version of onnxruntime or corrupted installation

**Fix**:
```bash
pip3 uninstall onnxruntime
pip3 install onnxruntime
```

#### Issue: Python command hangs indefinitely

**Cause**: ONNX runtime initialization can be slow on first run, or there's a compatibility issue

**Fix**:
- Check your Python version: `python3 --version` (should be 3.8+)
- Try onnxruntime-cpu instead: `pip3 install onnxruntime-cpu`
- Check CPU architecture compatibility (especially on Apple Silicon Macs)

#### Issue: "Model loaded successfully" but still no detections

**Cause**: Configuration issue or min_score threshold too high

**Fix**:
1. Lower the `min_score` threshold in config.yaml:
   ```yaml
   onnx_ner:
     min_score: 0.50  # Lower from 0.70
   ```

2. Check if text meets the heuristic requirements:
   - At least 8 characters
   - At least 40% letters
   - At least 5% spaces

#### Issue: Detections work but are incorrect

**Cause**: The model may have limitations

**Fix**:
- The dslim/bert-base-NER model is trained on CoNLL-2003 dataset
- It detects: PERSON, ORG, LOC, MISC
- It may not work well on:
  - Names from non-Western cultures
  - Modern company names (especially tech companies)
  - Informal or conversational text
  - Domain-specific jargon

### Performance Considerations

ONNX NER inference adds latency to each request:
- **Typical latency**: 200-500ms per request (Python subprocess)
- **Timeout default**: 5000ms
- **Max text size**: 32KB

If you experience timeouts:

```yaml
sanitizer:
  detectors:
    onnx_ner:
      timeout_ms: 100  # Increase timeout
      max_bytes: 16384  # Reduce max size
```

### Disabling ONNX NER

If you want to fall back to regex-only detection:

```yaml
sanitizer:
  detectors:
    onnx_ner:
      enabled: false
```

This will only use regex patterns for email, phone, API keys, etc., but won't detect person names or organizations.

### Getting Help

If none of these solutions work:

1. **Enable debug logging** (add to your velar start command):
   ```bash
   VELAR_DEBUG=1 velar start
   ```

2. **Create a minimal test case**:
   ```bash
   # Create test file
   cat > /tmp/test_ner.json << 'EOF'
   {"prompt": "My name is John Smith"}
   EOF
   
   # Run detection
   velar test-sanitize /tmp/test_ner.json
   ```

3. **Check system logs**:
   ```bash
   # On macOS
   log show --predicate 'process == "velard"' --last 5m
   
   # Check audit log
   tail -100 ~/.velar/audit.log
   ```

4. **Report an issue** with:
   - Python version (`python3 --version`)
   - onnxruntime version (`python3 -c "import onnxruntime; print(onnxruntime.__version__)"`)
   - OS and architecture (`uname -a`)
   - Config file (`cat ~/.velar/config.yaml`)
   - Error logs

### Alternative: Native ONNX Runtime (Advanced)

For better performance, you can build velar with native ONNX runtime support (requires CGo):

```bash
# Install ONNX Runtime library
brew install onnxruntime  # macOS
# or download from https://github.com/microsoft/onnxruntime/releases

# Build with onnxruntime tag
cd prompt-shield
go build -tags onnxruntime -o bin/velard ./cmd/velard

# Set backend to native
export VELAR_ONNX_BACKEND=native
./bin/velard start
```

This eliminates the Python dependency but requires more complex setup.

