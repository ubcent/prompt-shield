.PHONY: build run test test-ner clean help

# Optional virtualenv support (override with PYTHON=...)
VENV_DIR ?= .venv
PYTHON ?= $(VENV_DIR)/bin/python

# Default target
help:
	@echo "Velar Makefile"
	@echo ""
	@echo "Build targets:"
	@echo "  make build    - Build velar and velard binaries"
	@echo "  make run      - Run velar start"
	@echo ""
	@echo "Test targets:"
	@echo "  make test     - Run all tests locally (no Docker required)"
	@echo "  make test-ner - Test ONNX NER detector with sample text"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean    - Remove local build artifacts"

build:
	@mkdir -p ./bin
	go build -o ./bin/velar ./cmd/velar
	go build -o ./bin/velard ./cmd/velard

run:
	go run ./cmd/velar start

# Run all tests locally
# Includes race detector to preserve the previous isolation guarantees.
test:
	@echo "🧪 Running full Go test suite locally..."
	go test ./... -race
	@echo "✅ Tests completed!"

# Test ONNX NER detector
test-ner:
	@echo "🔍 Testing ONNX NER detector..."
	@$(PYTHON) -c "import sys" >/dev/null 2>&1 || (echo "Missing Python or venv. Run: python3 -m venv $(VENV_DIR) && source $(VENV_DIR)/bin/activate && pip install numpy onnxruntime" && exit 1)
	@PYTHON_BIN=$(PYTHON) go run ./cmd/test-ner/main.go "My name is Jamie Allen and I work at Microsoft in Seattle"

# Cleanup
clean:
	rm -rf ./bin
