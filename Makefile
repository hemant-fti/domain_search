
.PHONY: run test build build-agent build-linux build-windows fmt vet clean

run:
	go run ./cmd/main

test:
	go test ./...

build:
	go build -o bin/hostscope.exe ./cmd/hostscope

build-agent:
	go build -trimpath -ldflags="-s -w" -o hostscope.exe ./cmd/main

# Linux AMD64 build
build-linux: export CGO_ENABLED = 0
build-linux: export GOOS = linux
build-linux: export GOARCH = amd64
build-linux:
	go build -buildvcs=false -trimpath -ldflags="-s -w" -o hostscope ./cmd/main

# Windows AMD64 build
build-windows: export CGO_ENABLED = 0
build-windows: export GOOS = windows
build-windows: export GOARCH = amd64
build-windows:
	go build -buildvcs=false -trimpath -ldflags="-s -w" -o hostscope-windows-amd64.exe ./cmd/main

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	go clean
