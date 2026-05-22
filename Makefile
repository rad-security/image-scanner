BINARY      := rad-image-scanner
PKG         := github.com/rad-security/image-scanner/internal/cli
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS     := -s -w -X $(PKG).version=$(VERSION) -X $(PKG).commit=$(COMMIT)
BIN_DIR     := bin

.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) ./

.PHONY: install
install:
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" ./

.PHONY: test
test:
	go test ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: check
check: vet lint test

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)

.DEFAULT_GOAL := build
