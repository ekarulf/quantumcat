.PHONY: all build build-freebsd helper test clean
# Override VERSION to stamp a release tag. Left empty, the binary describes
# itself from the commit metadata the Go toolchain stamps automatically, and
# reports its version as "devel".
VERSION ?=
LDFLAGS := $(if $(VERSION),-X github.com/ekarulf/quantumcat/internal/version.Version=$(VERSION))
all: build
build:
	mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/qcat ./cmd/qcat
build-freebsd:
	mkdir -p bin
	GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/qcat-freebsd-amd64 ./cmd/qcat
helper:
	mkdir -p bin
	swiftc -O -module-cache-path .build/swift-cache -o bin/qcat-se swift/qcat-se.swift
test:
	go test -race ./...
clean:
	go clean ./...
