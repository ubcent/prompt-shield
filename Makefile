.PHONY: build run test clean help

# Default target
help:
	@echo "PromptShield Makefile"
	@echo ""
	@echo "Build targets:"
	@echo "  make build    - Build psd and psctl binaries"
	@echo "  make run      - Run psctl start"
	@echo ""
	@echo "Test targets:"
	@echo "  make test     - Run all tests in Docker"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean    - Stop and remove Docker containers"

build:
	@mkdir -p bin
	go build -o bin/psd ./cmd/psd
	go build -o bin/psctl ./cmd/psctl

run:
	go run ./cmd/psctl start

# Run all tests in Docker
test:
	@echo "🚀 Starting Docker services and running tests..."
	docker-compose up --build --abort-on-container-exit --exit-code-from test test
	@docker-compose down
	@echo "✅ Tests completed!"

# Cleanup
clean:
	docker-compose down -v
	docker-compose rm -f

