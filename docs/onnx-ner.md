# ONNX NER (Named Entity Recognition)

## Overview

Velar includes an ONNX-based Named Entity Recognition (NER) detector that can identify and sanitize:

- Person names (PERSON)
- Organizations (ORG)
- Locations (LOC)
- Miscellaneous entities (MISC)

This is in addition to the regex-based detectors for emails, phone numbers, API keys, and other secrets.

## Quick Start

### 1. Install Python Dependencies

The ONNX NER detector requires Python 3 with onnxruntime.

If your system Python is externally managed (common with Homebrew on macOS), use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install onnxruntime numpy
```

Otherwise, install directly:

```bash
pip3 install onnxruntime numpy
```

Velar automatically discovers the Python interpreter with the required dependencies. It checks the following locations in order:

1. `$PYTHON_BIN` environment variable (if set)
2. `.venv/bin/python` (relative to the working directory)
3. `~/.velar/venv/bin/python`
4. `python3` on PATH

To override, set `PYTHON_BIN` explicitly:

```bash
export PYTHON_BIN=/path/to/python
```

### 2. Download the NER Model

```bash
velar model download ner_en
```

This downloads the `dslim/bert-base-NER` model (~400MB) to `~/.velar/models/ner_en/`.

### 3. Enable ONNX NER in Configuration

Edit `~/.velar/config.yaml`:

```yaml
sanitizer:
  enabled: true
  detectors:
    onnx_ner:
      enabled: true      # Enable NER detection
      max_bytes: 32768   # Max text size to process
      timeout_ms: 5000   # Inference timeout (ms)
      min_score: 0.70    # Minimum confidence threshold
```

### 4. Start Velar

```bash
velar start
```

You should see:
```
proxy: ONNX NER health check passed - detector is working
```

## Testing

Test the detector directly:

```bash
# Using the test command
PYTHON_BIN="$PWD/.venv/bin/python" go run ./cmd/test-ner/main.go "My name is Jane Doe and I work at Acme Corp"

# Or using Makefile
make test-ner
```

Expected output:
```
=== ONNX NER Test ===
Text: "My name is Jane Doe and I work at Acme Corp"

OK: detection completed in 45ms
Found 2 entities:

#     Type         Text                           Start  End    Score
-----------------------------------------------------------------------
1     PERSON       Jane Doe                       11     19     0.99
2     ORG          Acme Corp                      34     43     0.95
```

## How It Works

### Architecture

```
HTTP Request
    |
    v
JSON Body Extraction
    |
    v
Field Scanning (prompt, content, message, etc.)
    |
    v
Hybrid Detector
    |-- Fast Regex Detectors (email, phone, API keys)
    `-- ONNX NER Detector (person, org, location)
           |
           v
       Tokenization (BERT WordPiece)
           |
           v
       Python subprocess
           |
           v
       ONNX Runtime Inference
           |
           v
       Entity Recognition
    |
    v
Entity Masking
    |
    v
Sanitized Request
```

### Detection Flow

1. **Request arrives** with JSON body
2. **JSON fields extracted** (looks for `prompt`, `content`, `message`, `text`, `input`, `parts`)
3. **Heuristic check**: Text must have:
   - At least 8 characters
   - At least 40% letters
   - At least 5% spaces
4. **Tokenization**: Text is tokenized using BERT WordPiece tokenizer
5. **Inference**: Python subprocess runs ONNX model inference
6. **Entity extraction**: BIO tags are converted to entity spans
7. **Filtering**: Entities below `min_score` threshold are filtered out
8. **Masking**: Entities are replaced with placeholders like `[PERSON_1]`, `[ORG_1]`

### Example

**Original request:**
```json
{
  "prompt": "Send an email to John Smith at john@acme.com about the API key sk-1234"
}
```

**Sanitized request:**
```json
{
  "prompt": "Send an email to [PERSON_1] at [EMAIL_1] about the API key [API_KEY_1]"
}
```

**Audit log entry:**
```json
{
  "sanitized": true,
  "sanitized_items": [
    {"type": "person", "original": "John Smith", "placeholder": "[PERSON_1]"},
    {"type": "email", "original": "john@acme.com", "placeholder": "[EMAIL_1]"},
    {"type": "api_key", "original": "sk-1234", "placeholder": "[API_KEY_1]"}
  ]
}
```

## Configuration Options

### `enabled` (boolean, default: false)

Enable or disable ONNX NER detection.

```yaml
onnx_ner:
  enabled: true
```

### `max_bytes` (int, default: 32768)

Maximum text size to process. Texts larger than this will skip NER detection (but still use regex detectors).

```yaml
onnx_ner:
  max_bytes: 16384  # Process up to 16KB
```

### `timeout_ms` (int, default: 40)

Maximum time to wait for inference. If exceeded, falls back to regex-only detection.

```yaml
onnx_ner:
  timeout_ms: 100  # Allow up to 100ms
```

### `min_score` (float, default: 0.70)

Minimum confidence score (0.0 to 1.0) for an entity to be kept. Lower values will detect more entities but with potentially more false positives.

```yaml
onnx_ner:
  min_score: 0.50  # More sensitive, may have false positives
```

## Performance Considerations

### Latency

- **Typical inference time**: 20-50ms per request
- **First request**: May be slower (~500ms) due to model loading
- **Timeout protection**: If inference takes too long, automatically falls back to regex-only

### Memory

- **Model size**: ~400MB on disk
- **Runtime memory**: ~512MB when loaded
- **Python subprocess**: ~100-200MB per inference

### Optimization Tips

1. **Reduce max_bytes** for faster processing:
   ```yaml
   max_bytes: 8192  # Only process short texts
   ```

2. **Increase timeout** if you see timeout warnings:
   ```yaml
   timeout_ms: 200
   ```

3. **Adjust min_score** based on your needs:
   - Higher (0.80-0.95): Fewer false positives, may miss some entities
   - Lower (0.50-0.70): More detections, may have false positives

## Troubleshooting

### "ONNX NER unavailable - model not loaded"

**Cause**: Model files not found

**Solution**:
```bash
velar model download ner_en
```

### "Python onnxruntime may be hanging on import"

**Cause**: Python dependencies not installed or incompatible

**Solution**:
```bash
python3 -m pip install --upgrade onnxruntime numpy
```

If you installed into a virtual environment, Velar will auto-discover `.venv/bin/python`. You can also override with:

```bash
export PYTHON_BIN=/path/to/venv/bin/python
```

### "inference timeout after 40ms"

**Cause**: Inference is too slow for the configured timeout

**Solution**: Increase timeout in config:
```yaml
onnx_ner:
  timeout_ms: 100
```

### No entities detected but text has names

**Possible causes**:
1. **Confidence too low**: Lower `min_score`
2. **Text doesn't meet heuristics**: Check that text has enough letters, spaces, and punctuation
3. **Model limitations**: The model may not recognize certain types of names or entities

### For detailed troubleshooting, see:
See `docs/onnx-ner-troubleshooting.md`.

## Model Information

- **Name**: dslim/bert-base-NER
- **Source**: [Hugging Face](https://huggingface.co/dslim/bert-base-NER)
- **Architecture**: BERT-base with token classification head
- **Training data**: CoNLL-2003 dataset
- **F1 Score**: 0.93
- **License**: MIT
- **Entity types**: PERSON, ORG, LOC, MISC

### Limitations

- Trained primarily on English news text
- May not work well on:
  - Non-English text
  - Code or technical content
  - Informal chat/text messages
  - Names from non-Western cultures
  - Modern company names (especially tech startups)

## Advanced: Native ONNX Runtime

For better performance, you can build velar with native ONNX Runtime support (eliminates Python dependency):

```bash
# Install ONNX Runtime library
brew install onnxruntime  # macOS

# Build with native support
go build -tags onnxruntime -o bin/velard ./cmd/velard

# Use native backend
export VELAR_ONNX_BACKEND=native
./bin/velard start
```

**Note**: This requires CGo and is more complex to set up.

## Disabling ONNX NER

To use only regex-based detection:

```yaml
sanitizer:
  enabled: true
  detectors:
    onnx_ner:
      enabled: false  # Disable NER
  types:
    - email
    - phone
    - api_key
    # ... other regex detectors
```

## Examples

### Example 1: Person Name Detection

**Input:**
```
"Do you happen to know who Jamie Allen is?"
```

**Detected entities:**
- `Jamie Allen` -> PERSON (score: 0.95)

**Output:**
```
"Do you happen to know who [PERSON_1] is?"
```

### Example 2: Mixed Entities

**Input:**
```
"Contact Jane Smith at Microsoft's Seattle office or email jane@microsoft.com"
```

**Detected entities:**
- `Jane Smith` -> PERSON (score: 0.98)
- `Microsoft` -> ORG (score: 0.95)
- `Seattle` -> LOC (score: 0.92)
- `jane@microsoft.com` -> EMAIL (score: 1.00, regex)

**Output:**
```
"Contact [PERSON_1] at [ORG_1]'s [LOC_1] office or email [EMAIL_1]"
```

### Example 3: Conversation Context

**Input:**
```json
{
  "messages": [
    {"role": "user", "content": "I'm meeting with John tomorrow"},
    {"role": "assistant", "content": "Great! Where are you meeting John?"}
  ]
}
```

**Output:**
```json
{
  "messages": [
    {"role": "user", "content": "I'm meeting with [PERSON_1] tomorrow"},
    {"role": "assistant", "content": "Great! Where are you meeting [PERSON_1]?"}
  ]
}
```

Note: The same person name gets the same placeholder across the entire request.

## See Also

- [Configuration Guide](configuration.md)
- [ONNX NER Troubleshooting](onnx-ner-troubleshooting.md)
- [Security Model](security.md)

