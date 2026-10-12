# Infrastructure console

The infrastructure console is for privileged operators, not application users.
Every endpoint under `/api/v1/infrastructure/**` requires the
`INFRASTRUCTURE_INTERNAL` authority and records sensitive client actions in
`auth.audit_event`.

## First operator

Flyway creates only the `INFRASTRUCTURE_INTERNAL` role. On a new deployment,
set these deployment secrets for one startup:

```text
INFRASTRUCTURE_BOOTSTRAP_USERNAME=...
INFRASTRUCTURE_BOOTSTRAP_EMAIL=...
INFRASTRUCTURE_BOOTSTRAP_PASSWORD=at-least-16-characters
```

The application creates an active operator only if no operator with that
username already exists. Remove those bootstrap secrets after the first
successful startup. Never add a privileged password to Flyway migrations.

For local setup, migration `V1_0_6` also creates `infrastructure` with the
password supplied by `INFRASTRUCTURE_ADMIN_PASSWORD` (`admin1234` by default)
and registers `conecta-infrastructure-portal` as a public PKCE client. Override
the password before applying the migration anywhere other than local development.

## OAuth client controls

| Operation | Endpoint |
| --- | --- |
| List | `GET /api/v1/infrastructure/clients` |
| Create | `POST /api/v1/infrastructure/clients` |
| Rotate confidential secret | `POST /api/v1/infrastructure/clients/{clientId}/secret-rotations` |
| Delete client and its authorizations | `DELETE /api/v1/infrastructure/clients/{clientId}` |

Client secrets are returned exactly once on create/rotation. Store them in a
secret manager immediately. A public web/mobile client must set
`publicClient: true`; it has no secret and PKCE is mandatory.
