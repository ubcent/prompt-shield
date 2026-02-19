.PHONY: build run test test-race

build:
	go build ./cmd/psd
	go build ./cmd/psctl

run:
	go run ./cmd/psctl start

test:
	go test ./...

test-race:
	go test -race ./...
