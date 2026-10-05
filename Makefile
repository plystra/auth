GO ?= go
SQLC ?= sqlc

.PHONY: gen check test build migrate

gen:
	$(SQLC) generate
	$(GO) run ./internal/tools/schema-snapshot

check: gen
	$(GO) test -race ./...
	$(GO) vet ./...

test:
	$(GO) test ./...

build:
	$(GO) build ./cmd/plystra-auth

migrate:
	$(GO) run ./cmd/plystra-auth migrate
