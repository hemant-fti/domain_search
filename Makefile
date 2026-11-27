.PHONY: run test test-race vet fmt check-deps check build build-agent build-linux build-windows cross clean

PKG := ./cmd/hostscope

ifeq ($(OS),Windows_NT)
    BINARY_NAME := hostscope.exe
    BUILD_ENV :=
else
    BINARY_NAME := hostscope
    BUILD_ENV := CGO_ENABLED=0
endif

run:
	go run $(PKG)

test:
	go test ./...

# The race detector needs cgo (a C compiler).
test-race:
	CGO_ENABLED=1 go test -race ./...

vet:
	go vet ./...
	GOOS=windows go vet ./...

fmt:
	gofmt -w .

# Enforce docs/dependency-rules.md for both target platforms.
check-deps:
	go test ./tests/ -run 'TestDependencyRules|TestReusablePackagesDoNotLogGlobally' -count=1

# Everything CI should run.
check: vet test check-deps cross
	@test -z "$$(gofmt -l $$(git ls-files '*.go'))" || (gofmt -l $$(git ls-files '*.go'); exit 1)

build:
	$(BUILD_ENV) go build -o $(BINARY_NAME) $(PKG)

build-agent:
	go build -trimpath -ldflags="-s -w" -o hostscope.exe $(PKG)

# Linux AMD64 build
build-linux: export CGO_ENABLED = 0
build-linux: export GOOS = linux
build-linux: export GOARCH = amd64
build-linux:
	go build -buildvcs=false -trimpath -ldflags="-s -w" -o hostscope $(PKG)

# Windows AMD64 build
build-windows: export CGO_ENABLED = 0
build-windows: export GOOS = windows
build-windows: export GOARCH = amd64
build-windows:
	go build -buildvcs=false -trimpath -ldflags="-s -w" -o hostscope-windows-amd64.exe $(PKG)

# Compile every package, including Windows test binaries, for both targets.
cross:
	GOOS=linux GOARCH=amd64 go build ./...
	GOOS=windows GOARCH=amd64 go build ./...
	for p in $$(GOOS=windows go list ./...); do GOOS=windows GOARCH=amd64 go test -c -o /dev/null $$p || exit 1; done

clean:
	go clean
