# Plystra Auth implementation rules

This repository is the Go backend for Plystra Auth. Read `../auth-docs/tech-stack.md` before changing architecture.

- Go 1.26+, PostgreSQL 17+, pgx v5, Huma v2, sqlc, goose v3, River, jwx v3, and `caarlos0/env/v11` are the fixed stack.
- SQL migrations are the schema source of truth. Queries live in `internal/<domain>/queries/*.sql` and generated sqlc output is never edited.
- Register JSON routes only through `internal/route.Register` with a complete `route.Spec`. Non-JSON protocol handlers must be registered in the same route declaration registry.
- `internal/authz/engine` and `internal/authz/delta` are pure functions. They cannot import database, HTTP, OS, or call `time.Now`.
- `store.InTx` is the only transaction entry point.
- Secrets use `internal/secret.Secret` and must never be logged or returned after creation.
- Run `make gen` after changing migrations, queries, or API types. Run `make check` before claiming completion.
- Do not add an ORM, Redis, message broker, or a second persistence system.

## Change and verification map

The fixed architecture and its rationale are defined in [`../auth-docs/tech-stack.md`](../auth-docs/tech-stack.md). Keep each change at its documented source of truth and run the corresponding generator or check:

| Change | Source of truth | Verify afterward |
| --- | --- | --- |
| Schema or migration | `migrations/` | `make gen` |
| SQL query | `internal/<domain>/queries/` | `make gen` |
| JSON route or API type | Go input/output types and `route.Register` | `make gen` |
| Authorization policy | `internal/authz/engine` and `internal/authorization` | focused tests, then `make check` |
| Frontend | `web/` | `make web-check` |
| Any backend change | the owning package and its tests | `make check` |

Do not edit generated sqlc, schema, or OpenAPI files by hand. A completed change must leave generated output clean and must include an automated test for changed behavior.
