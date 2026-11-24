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

### Set up workforce sign-in

1. A Space administrator creates an OIDC or SAML connection at
   `POST /v1/spaces/{id}/sso-connections` with request-bound step-up.
   For SAML, register the active connection with the IdP using the
   [service provider metadata](#register-a-saml-service-provider).
2. The administrator creates a directory at `POST /v1/spaces/{id}/directories`, selects
   `sso_connection_id` and the IdP's stable `sso_identity_claim`, and stores the SCIM
   token returned once. Provision the employee through `/scim/v2/{dir_id}/Users`.
   The employee's `externalId` must exactly match the selected IdP claim.
3. Start the employee's login at `GET /v1/sso/{connection_id}/start` and submit the IdP
   response to the matching callback. The account can renew its session at `/v1/auth/refresh`.
   A hosted OIDC interaction can use an enterprise OIDC connection registered with the HTTPS
   issuer origin and the `/oidc/upstream` callback path. The same-origin page submits the IdP
   code and state to `/v1/auth/oidc-interactions/{id}/sso/complete` with the original interaction
   cookie. Auth returns the next consent step and signed-in account. The built-in hosted pages
   are still under development.
4. On departure, use SCIM to set `active=false` with the current resource `If-Match` value.
   Related sessions and refresh credentials lose online access on commit, including sessions
   established through that binding before switching members. Reprovisioned employees sign in again.

Migration `0068` revokes existing enterprise SSO sessions whose original binding was unrecorded.
Deploy updated Auth binaries with the migration and plan for those users to sign in again.

### Register a SAML service provider

After creating the active SAML connection from the IdP's metadata, complete request-bound
step-up for `sso_connections.get` with the Space and connection IDs. Then read
`GET /v1/spaces/{id}/sso-connections/{conn_id}` with the same administrator session.
Save the decoded `data.saml_sp_metadata` string as an XML file and import it in the
IdP's SAML application settings. The XML carries the SP entity ID and the exact
HTTP-POST assertion consumer URL.

Configure the IdP to sign the SAML Response and Assertion, using SHA-256 or stronger.
Allow unsigned AuthnRequests as declared in the XML. In Keycloak, review **Client signature
required** after import and set it off if the import defaulted it on. Enable **Force POST
binding**, **Sign documents** and **Sign assertions**. When using SCIM, configure the stable
attribute selected on the directory and use a stable NameID. Verify a fresh sign-in as a
provisioned user before enforcing SSO for the Space.

### Monitor SAML certificate coverage

Schedule the read-only check on a trusted deployment host. Provide the database
connection through `PLYSTRA_AUTH_DATABASE_URL` in the monitor's secret environment.

```sh
plystra-auth sso check-saml-certificates --within 720h
```

An exit status of `2` means the JSON report identifies at least one connection that
requires attention. Alert on the Space, connection, and reported status. An exit
status of `1` means the check failed. Route it to the deployment operator and alert
if the scheduled check stops reporting. A healthy run exits `0`.

For `coverage_ending`, import the replacement metadata before `coverage_until`.
Confirm a fresh sign-in with the new IdP signer before removing the old certificate.
`no_current_signer` and `invalid_trust` require immediate investigation. The report
calculates continuous coverage from the certificates configured in Auth. Confirm
which certificate the IdP actually uses during the rotation.

### Provision signing keys

Run `plystra-auth migrate` before serving. In deployments that configure an encrypted
ES256 PEM, use the same initial file, issuer and signing-key encryption key on every replica.
The first successful startup initializes the shared PostgreSQL signing key set. Later starts
load that set using the configured issuer and encryption key. Running replicas read the
database ring for issuance, verification, JWKS and readiness. After a rotation commits,
new tokens use the active key and JWKS publishes the active and retiring public keys.
An unreadable ring makes the service unready. Requests that need its keys return HTTP
503 until access is restored. Failed issuance rolls back the consumption of an OAuth
authorization code or a session refresh token, allowing the caller to retry.
The mounted file supplies the initial key when the database has no signing keys.
Development without a configured file continues to use an ephemeral process-local key.

Keep the signing-key encryption key outside PostgreSQL and available to restore its backups.

### Integrate application sign-in

1. Register an application with its exact HTTPS callback and `human_oidc_enabled: true`.
   An application that only signs users in can supply an empty permission manifest.
   Select `client_secret_basic` for a confidential server client and securely retain the
   one-time client secret.
2. Load the issuer's OpenID configuration from `/.well-known/openid-configuration`.
   Begin a code request with `scope=openid`, unique state and nonce, and a PKCE S256
   challenge. The authorization API returns the pending request for authenticated consent.
3. Submit the consent decision to `POST /oauth/authorize` with a user access token.
   The application receives the code at its registered callback after consent navigation.
   Verify state, exchange the code with its original callback and PKCE verifier, and validate
   the signed ID token against the issuer's JWKS, issuer, audience, expiry and original nonce.
4. Use the returned access token with UserInfo for approved claims. To roll a confidential
   client's credentials, use `POST /v1/applications/{app_id}/oauth-client-secret/rotate`
   with request-bound step-up and choose the old secret's overlap window.

## Verify a checkout

Install the Go version declared in [go.mod](go.mod), Make and Docker. Run `make check` from
a clean checkout for generated-file consistency, lint, race-enabled tests, vet and
vulnerability checks. Integration tests start disposable PostgreSQL containers.
