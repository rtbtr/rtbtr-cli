.PHONY: build clean release lint fmt vet test check tidy

BINARY_NAME := rtbtr
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME  := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS     := -s -w \
	-X github.com/rtbtr/rtbtr-cli/internal/version.Version=$(VERSION) \
	-X github.com/rtbtr/rtbtr-cli/internal/version.Commit=$(COMMIT) \
	-X github.com/rtbtr/rtbtr-cli/internal/version.BuildTime=$(BUILD_TIME)

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/rtbtr

clean:
	rm -rf bin/ dist/

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------

lint:
	golangci-lint run ./...

fmt:
	gofmt -w -s .

fmt-check:
	@test -z "$$(gofmt -s -l .)" || (echo "unformatted files:" && gofmt -s -l . && exit 1)

vet:
	go vet ./...

test:
	go test -v -race -cover ./...

check: fmt-check lint vet test

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

tidy:
	go mod tidy

# ---------------------------------------------------------------------------
# Release — cross-compile for all supported platforms
# ---------------------------------------------------------------------------

release:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64       ./cmd/rtbtr
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-arm64       ./cmd/rtbtr
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-amd64      ./cmd/rtbtr
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-arm64      ./cmd/rtbtr
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-windows-amd64.exe ./cmd/rtbtr
