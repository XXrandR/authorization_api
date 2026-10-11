# Conecta Authorization API

OAuth 2.1 authorization server for Conecta applications. It issues signed JWT
access tokens and publishes OpenID Connect discovery/JWKS metadata. The server
supports browser, Android, iOS, and web clients through **authorization code
with PKCE**. It deliberately does **not** support the resource-owner password
grant.

## Security contract

- Browser/native clients: authorization code + PKCE (`S256` only).
- Refresh tokens: supported for clients explicitly registered with that grant.
- Machine-to-machine clients: client credentials, registered separately.
- JWT access tokens: RS256, stable key ID, issuer configured externally.
- Role claim: `roles`; scopes remain in the standard `scope` claim.
- Signing key: an externally managed PKCS#12 file. It is never generated at
  startup and is ignored by Git.

See [docs/oauth2.1-contract.md](docs/oauth2.1-contract.md) for endpoint and
client-registration requirements.

## Local setup

1. Create a local signing key:

   ```bash
   export AUTHORIZATION_KEY_STORE_PASSWORD='use-a-local-secret'
   sh scripts/generate-local-signing-key.sh
   ```

2. Copy `src/main/resources/application-local.properties.example` to
   `src/main/resources/application-local.properties`, then set the local
   database and keystore values. This file is intentionally ignored.

3. Start the server:

   ```bash
   ./gradlew bootRun --args='--spring.profiles.active=local'
   ```

Flyway owns the `auth` schema. Do not apply `references.sql` or other ad-hoc
schema scripts to a database managed by this application.

## Metadata

```bash
curl http://localhost:8080/.well-known/oauth-authorization-server | jq
curl http://localhost:8080/oauth2/jwks | jq
```
