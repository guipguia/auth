.PHONY: proto clean build run test test-coverage test-race test-all test-internal coverage-report

# Ensure Go bin is in PATH
GOPATH := $(shell go env GOPATH)
PATH := $(GOPATH)/bin:$(PATH)
export PATH


proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/proto/auth/v1/auth.proto

clean:
	rm -f api/proto/auth/v1/*.pb.go
	rm -f coverage.out coverage.html

build:
	go build -o bin/auth-server cmd/server/main.go

run:
	go run cmd/server/main.go

# Run all tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out

# Run tests with race detection
test-race:
	go test -v -race ./...

# Run all tests with coverage and race detection (CI mode)
test-all:
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | grep total

# Run only internal package tests
test-internal:
	go test -v -coverprofile=coverage.out -covermode=atomic ./internal/...
	go tool cover -func=coverage.out

# Generate HTML coverage report
coverage-report: test-coverage
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

docker-build:
	docker build -t chassis/auth:latest .

install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest