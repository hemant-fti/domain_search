.PHONY: run test build build-agent build-app fmt vet clean

run:
	go run ./cmd/main

test:
	go test ./...

build:
	go build -o bin/hostscope.exe ./cmd/hostscope

build-agent:
	go build -trimpath -ldflags="-s -w" -o dist/hostscope.exe ./cmd/main

build-app: export CGO_ENABLED = 0
build-app: export GOOS = linux
build-app: export GOARCH = amd64
build-app:
	go build -buildvcs=false -trimpath -ldflags="-s -w" -o hostscope ./cmd/main

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	go clean
