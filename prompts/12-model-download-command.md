# Task: NER Model Download Command

## Objective
Add CLI command to download and manage NER models for local PII detection.

## Current State
- NER models are expected to exist in `internal/models/ner_en/`
- No automated way to download or update models
- Users must manually place model files
- Unclear which models are available or installed

## Specification

### Functional Requirements
1. `velar model list` - show available and installed models:
   - Model name, language, size, status (installed/not installed)
   - Model description and supported entity types
2. `velar model download <name>` - download specific model:
   - Progress bar with download percentage
   - Verify checksum after download
   - Extract to correct location
   - Validate model loads correctly
3. `velar model download --all` - download all recommended models
4. `velar model info <name>` - show detailed model information:
   - Version, size, supported types, accuracy metrics
   - Model source URL and license
5. `velar model remove <name>` - remove installed model
6. `velar model verify` - verify integrity of installed models

### Technical Requirements
1. Implement `cmd/velar/model.go` with model management commands
2. Model registry as embedded JSON or fetched from GitHub:
   ```json
   {
     "models": [
       {
         "name": "ner_en",
         "language": "en",
         "version": "1.0.0",
         "url": "https://github.com/ubcent/velar-models/releases/download/v1.0.0/ner_en.tar.gz",
         "checksum": "sha256:abc123...",
         "size_bytes": 52428800,
         "entity_types": ["PERSON", "ORG", "EMAIL", "PHONE"],
         "description": "English NER model for PII detection",
         "license": "MIT"
       }
     ]
   }
   ```
3. Download with progress tracking:
   - Use `net/http` with progress callback
   - Show speed and ETA
4. Model storage location: `~/.velar/models/<name>/`
5. Atomic installation: download to temp, verify, then move
6. Graceful handling of network failures with retry

### Acceptance Criteria
- [ ] `velar model list` shows available models
- [ ] `velar model download ner_en` downloads and installs model
- [ ] Progress bar shows accurate download progress
- [ ] Checksum verification catches corrupted downloads
- [ ] Model loads successfully after installation
- [ ] `velar model verify` detects corrupted models
- [ ] Works offline for already-installed models
- [ ] All existing tests pass

### Testing Requirements
1. Mock HTTP server for testing downloads
2. Test checksum verification with tampered files
3. Test with slow network (simulated)
4. Test disk full scenario
5. Test concurrent downloads (should queue)
6. Add tests in `cmd/velar/model_test.go`
7. Add integration test that downloads real model

### Files to Create/Modify
- `cmd/velar/model.go` - NEW: model management commands
- `cmd/velar/model_test.go` - NEW: model tests
- `cmd/velar/main.go` - register model command
- `internal/models/registry.go` - NEW: model registry
- `internal/models/registry.json` - NEW: model metadata
- `internal/models/downloader.go` - NEW: download logic
- `internal/models/downloader_test.go` - NEW: downloader tests
- `internal/detect/onnx_ner_detector.go` - use new model paths
- `README.md` - document model commands

## Output Examples

### List Models
```
$ velar model list

Available Models
────────────────────────────────────────────────────────────────
NAME      LANG  SIZE    STATUS       TYPES
────────────────────────────────────────────────────────────────
ner_en    en    50 MB   installed    PERSON, ORG, EMAIL, PHONE
ner_multi multi 120 MB  not installed PERSON, ORG, EMAIL, PHONE
ner_de    de    48 MB   not installed PERSON, ORG
────────────────────────────────────────────────────────────────

Installed: 1/3 models
Total size: 50 MB

Tip: Use 'velar model download <name>' to install a model
```

### Download Model
```
$ velar model download ner_en

Downloading ner_en v1.0.0
Source: https://github.com/ubcent/velar-models/releases/...

Downloading... ████████████████████░░░░░░░░  75% | 38 MB / 50 MB | 2.1 MB/s | ETA 5s

Verifying checksum... ✓
Extracting... ✓
Validating model... ✓

✓ Model ner_en installed successfully

Model supports: PERSON, ORG, EMAIL, PHONE
Location: ~/.velar/models/ner_en/

To enable, set in config.yaml:
  sanitizer:
    detectors:
      onnx_ner:
        enabled: true
```

### Model Info
```
$ velar model info ner_en

NER Model: ner_en
────────────────────────────────────────
Status:         Installed
Version:        1.0.0
Language:       English
Size:           50 MB
Location:       ~/.velar/models/ner_en/

Capabilities
────────────────────────────────────────
Entity Types:   PERSON, ORG, GPE, EMAIL, PHONE,
                CREDIT_CARD, SSN
Accuracy:       F1 score: 0.93 (on CoNLL-2003)

Technical Details
────────────────────────────────────────
Format:         ONNX
Architecture:   BERT-base fine-tuned
Input:          Max 512 tokens
License:        MIT

Source
────────────────────────────────────────
URL:            https://github.com/ubcent/velar-models
Checksum:       sha256:abc123def456...
```

### Verify Models
```
$ velar model verify

Verifying installed models...

ner_en
  ├─ Checksum... ✓
  ├─ Files...    ✓
  └─ Loadable... ✓

All models verified successfully
```

### Remove Model
```
$ velar model remove ner_en

Remove model 'ner_en' (50 MB)?
This will delete ~/.velar/models/ner_en/

Continue? (y/N): y

Removing model... ✓
Model ner_en removed successfully
```

## Model Registry Format

### registry.json
```json
{
  "version": "1.0.0",
  "models": [
    {
      "name": "ner_en",
      "display_name": "English NER Model",
      "version": "1.0.0",
      "language": "en",
      "url": "https://github.com/ubcent/velar-models/releases/download/v1.0.0/ner_en.tar.gz",
      "checksum": "sha256:abc123def456789...",
      "size_bytes": 52428800,
      "entity_types": ["PERSON", "ORG", "GPE", "EMAIL", "PHONE", "CREDIT_CARD", "SSN"],
      "description": "BERT-based NER model for English PII detection",
      "architecture": "BERT-base",
      "accuracy": {
        "f1_score": 0.93,
        "benchmark": "CoNLL-2003"
      },
      "requirements": {
        "min_memory_mb": 512,
        "onnx_version": "1.12+"
      },
      "license": "MIT",
      "recommended": true
    },
    {
      "name": "ner_multi",
      "display_name": "Multilingual NER Model",
      "version": "1.0.0",
      "language": "multi",
      "url": "https://github.com/ubcent/velar-models/releases/download/v1.0.0/ner_multi.tar.gz",
      "checksum": "sha256:def789abc123456...",
      "size_bytes": 125829120,
      "entity_types": ["PERSON", "ORG", "EMAIL", "PHONE"],
      "description": "Multilingual NER model (en, es, fr, de, it)",
      "architecture": "mBERT",
      "accuracy": {
        "f1_score": 0.89,
        "benchmark": "CoNLL-X"
      },
      "requirements": {
        "min_memory_mb": 1024,
        "onnx_version": "1.12+"
      },
      "license": "MIT",
      "recommended": false
    }
  ]
}
```

## Implementation Notes

### Downloader with Progress
```go
type ProgressCallback func(downloaded, total int64, speed float64)

func DownloadWithProgress(url, dest string, onProgress ProgressCallback) error {
    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    out, err := os.Create(dest)
    if err != nil {
        return err
    }
    defer out.Close()

    total := resp.ContentLength
    var downloaded int64
    start := time.Now()

    buffer := make([]byte, 32*1024)
    for {
        n, err := resp.Body.Read(buffer)
        if n > 0 {
            out.Write(buffer[:n])
            downloaded += int64(n)

            elapsed := time.Since(start).Seconds()
            speed := float64(downloaded) / elapsed / 1024 / 1024 // MB/s
            onProgress(downloaded, total, speed)
        }
        if err == io.EOF {
            break
        }
        if err != nil {
            return err
        }
    }
    return nil
}
```

### Checksum Verification
```go
func VerifyChecksum(file, expected string) error {
    f, err := os.Open(file)
    if err != nil {
        return err
    }
    defer f.Close()

    h := sha256.New()
    if _, err := io.Copy(h, f); err != nil {
        return err
    }

    actual := hex.EncodeToString(h.Sum(nil))
    if "sha256:"+actual != expected {
        return fmt.Errorf("checksum mismatch: expected %s, got sha256:%s", expected, actual)
    }
    return nil
}
```

## Non-Goals
- Automatic model updates (manual only)
- Model training or fine-tuning
- Multiple model versions installed simultaneously
- Model compression or optimization
- CDN or mirror support (single source URL only)
