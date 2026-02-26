.PHONY: build run test clean help

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

# Cleanup
clean:
	rm -rf ./bin
