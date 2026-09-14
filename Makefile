.PHONY: all build build-freebsd helper test clean
all: build
build:
	mkdir -p bin
	go build -trimpath -o bin/qcat ./cmd/qcat
build-freebsd:
	mkdir -p bin
	GOOS=freebsd GOARCH=amd64 go build -trimpath -o bin/qcat-freebsd-amd64 ./cmd/qcat
helper:
	mkdir -p bin
	swiftc -O -module-cache-path .build/swift-cache -o bin/qcat-se swift/qcat-se.swift
test:
	go test -race ./...
clean:
	go clean ./...
