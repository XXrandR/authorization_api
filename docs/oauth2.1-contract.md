# OAuth 2.1 contract

## Supported grants

| Client type | Grant | Requirements |
| --- | --- | --- |
| Web SPA, Android, iOS | `authorization_code` | PKCE using `S256`; registered exact redirect URI |
| Web SPA, Android, iOS | `refresh_token` | Client must have obtained the token via authorization code |
| Backend service | `client_credentials` | Confidential client authentication; no end-user identity |

The password grant is intentionally unsupported. A client must never collect a
user password and exchange it directly at `/oauth2/token`.

## Authorization code flow

1. The client creates a cryptographically random `code_verifier` and its
   SHA-256/base64url `code_challenge`.
2. It redirects the user agent to `/oauth2/authorize` with
   `response_type=code`, its `client_id`, an exact `redirect_uri`, requested
   scopes, `state`, `code_challenge`, and `code_challenge_method=S256`.
3. The authorization server authenticates the user through its browser login
   session. The React login experience can replace the server-rendered login
   page, but it must submit credentials only to this authorization-server
   origin and preserve CSRF/session protections.
4. The client exchanges the returned code at `/oauth2/token` with its original
   `code_verifier`. Native and SPA clients do not use a client secret.

## Client registration policy

Client registration is an administrative operation and is not open to public
callers. Each registered client must have:

- a stable client identifier;
- explicit grant types and minimal scopes;
- exact HTTPS redirect URIs (loopback redirects are allowed for native local
  development);
- PKCE required for every public client;
- short authorization-code lifetime and refresh-token rotation;
- no client secret for a SPA or installed mobile app.

The current database repository supports registered clients. Add the protected
administrative client-management API only after defining its operator and audit
requirements; do not expose `JdbcRegisteredClientRepository` directly.

## Token validation

Resource APIs must validate `iss`, signature, expiry, audience, and required
scopes. They should retrieve signing keys from `/oauth2/jwks`, cache keys by
`kid`, and map the `roles` claim only when role-based access is required.

## Key management

`AUTHORIZATION_KEY_STORE` must be a `file:` URL to a PKCS#12 keystore holding
the configured RSA alias. Back up the key securely. Rotating keys requires a
JWKS overlap period: publish both the retiring and active public keys until all
tokens signed by the old key expire.
