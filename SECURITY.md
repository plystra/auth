# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the GitHub Security
Advisory for `github.com/plystra/auth`. Do not open a public issue or include
credentials, production data, or an exploit that would expose another person.

Include the affected version or commit, the deployment surface, a minimal
reproduction, and the impact. Redact secrets from all attachments.

We acknowledge reports within 3 business days, provide an initial triage
within 7 business days, and give status updates at least every 14 days until
the issue is resolved or the report is closed. We coordinate a disclosure
date with the reporter after a fix is available.

## Supported versions

Only the latest released version and the current `main` branch receive
security fixes. Operators should run `make check`, apply migrations using the
documented forward-only process, and rotate affected credentials after a
confirmed incident.

## Scope

The service, its Go packages, SQL migrations, and the supported command-line
interface are in scope. Third-party dependencies, customer deployments,
business applications, and infrastructure outside this repository are out of
scope; reports about them should be sent to their respective maintainers.
