GO ?= go
SQLC ?= sqlc

.PHONY: gen check test build migrate openapi

gen:
	$(SQLC) generate
	$(GO) run ./internal/tools/schema-snapshot
	$(GO) run ./internal/tools/openapi

check: gen
	$(GO) test -race ./...
	$(GO) vet ./...
	git diff --check

test:
	$(GO) test ./...

build:
	$(GO) build ./cmd/plystra-auth

migrate:
	$(GO) run ./cmd/plystra-auth migrate

openapi:
	$(GO) run ./internal/tools/openapi
