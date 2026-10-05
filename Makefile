GO ?= go

.PHONY: gen check test build migrate openapi

gen:
	$(GO) tool sqlc generate
	$(GO) run ./internal/tools/schema-snapshot
	$(GO) run ./internal/tools/openapi

check: gen
	git diff --exit-code
	$(GO) tool golangci-lint run
	$(GO) test -race ./...
	$(GO) vet ./...
	$(GO) tool govulncheck ./...
	git diff --check

test:
	$(GO) test ./...

build:
	$(GO) build ./cmd/plystra-auth

migrate:
	$(GO) run ./cmd/plystra-auth migrate

openapi:
	$(GO) run ./internal/tools/openapi
