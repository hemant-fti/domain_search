.PHONY: run test build build-agent build-linux-amd64 build-linux-arm64 build-windows-amd64 fmt vet clean

ifeq ($(OS),Windows_NT)
MKDIR_DIST = if not exist dist mkdir dist
else
MKDIR_DIST = mkdir -p dist
endif

run:
	go run ./cmd/api

test:
	go test ./...

build:
	go build -o bin/domain-scout-api.exe ./cmd/agent

build-agent:
	go build -trimpath -ldflags="-s -w" -o dist/domain-scout.exe ./cmd/agent

build-linux-amd64: export CGO_ENABLED = 0
build-linux-amd64: export GOOS = linux
build-linux-amd64: export GOARCH = amd64
build-linux-amd64:
	$(MKDIR_DIST)
	go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/domain-scout-linux-amd64 ./cmd/agent

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	go clean
