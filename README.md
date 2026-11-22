# Plystra Auth

Plystra Auth is an identity and authorization backend for applications that serve people
and AI agents. It handles sign-in, membership in Spaces, resource-scoped grants, delegation,
approval and audit. Applications use the server API to check authority before acting on
their own resources. Enterprise connections support workforce sign-in and directory provisioning.

## Run locally

With Docker Compose, run this command from the repository root.

```sh
docker compose -f docker-compose.dev.yml up -d --build
```

The development stack starts PostgreSQL 17, applies migrations and starts Auth. It publishes
four ports on the IPv4 loopback interface and keeps the database in a named volume.
Once the service is ready, these requests return its readiness status and public signing keys.

```sh
curl --fail http://127.0.0.1:8090/readyz
curl --fail http://127.0.0.1:8080/.well-known/jwks.json
```

| Port | Purpose | API reference |
| --- | --- | --- |
| 8080 | Account and Agent access, OAuth, SSO and discovery | [Principal API](openapi/principal.json) |
| 8081 | Application backend checks, introspection and audit | [Server API](openapi/server.json) |
| 8082 | Operator authentication and deployment policy | [Operations API](openapi/ops.json) |
| 8090 | Health, readiness and metrics | `/healthz`, `/readyz`, `/metrics` |

### Create the first operator

Public registration starts closed. In a private terminal on the deployment host, initialize
the default Space and application once. Store the application key printed by `init`. Then
create the first operator. The following shell example reads a password from a private
file containing one line. Set `OPERATOR_PASSWORD_FILE` to that path and substitute the
intended operator's address.

```sh
docker compose -f docker-compose.dev.yml exec -T auth plystra-auth init
docker compose -f docker-compose.dev.yml exec -T auth plystra-auth operator bootstrap \
  --email owner@example.test --password-stdin < "$OPERATOR_PASSWORD_FILE"
```

The bootstrap command displays the operator's TOTP enrollment secret and its bootstrap API
key once. Enroll the factor, store the key securely and sign in using the password and
current TOTP code at `POST /ops/v1/auth/sign-in` on port 8082. A second bootstrap is refused.
Use the operations API to manage further operators, allowed origins, registration and session
policy. The Compose credentials and process-local signing key are for local development.

Stop the stack with `docker compose -f docker-compose.dev.yml down`. The database volume
persists. For an application example with its own database and online authorization checks,
see the [Invoice SaaS backend](examples/invoice-saas/README.md).

## Verify a checkout

Install the Go version declared in [go.mod](go.mod), Make and Docker. Run `make check` from
a clean checkout for generated-file consistency, lint, race-enabled tests, vet and
vulnerability checks. Integration tests start disposable PostgreSQL containers.
