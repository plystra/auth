GO ?= go

ifeq ($(OS),Windows_NT)
WEB_CHECK = if exist web (cd web && bun run typecheck && bun run test --run)
else
WEB_CHECK = if [ -d web ]; then cd web && bun run typecheck && bun run test --run; fi
endif

.PHONY: gen check web-check dev test build migrate openapi

gen:
	$(GO) tool sqlc generate
	$(GO) tool sqlc generate -f examples/invoice-saas/sqlc.yaml
	$(GO) run ./internal/tools/schema-snapshot
	$(GO) run ./internal/tools/openapi

# Each test package starts its own PostgreSQL container; cap concurrent startups.
check: export GOFLAGS += -p=4
check: gen
	git diff --exit-code
	$(MAKE) web-check
	$(GO) tool golangci-lint run
	$(GO) test -race ./...
	$(GO) vet ./...
	$(GO) tool govulncheck ./...
	git diff --check

web-check:
	@$(WEB_CHECK)

dev:
	docker compose -f docker-compose.dev.yml up --build

test:
	$(GO) test ./...

build:
	$(GO) build ./cmd/plystra-auth

migrate:
	$(GO) run ./cmd/plystra-auth migrate

openapi:
	$(GO) run ./internal/tools/openapi
