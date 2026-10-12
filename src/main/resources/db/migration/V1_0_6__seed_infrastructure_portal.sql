-- Local/bootstrap infrastructure operator. Password comes from the Flyway
-- placeholder configured in application.properties; never change this
-- migration after it has been applied.
INSERT INTO auth.identity (
    id, username, email, password_hash, email_verified, phone_verified,
    is_active, is_blocked, person_id
)
VALUES (
    gen_random_uuid(),
    '${infrastructure_admin_username}',
    '${infrastructure_admin_email}',
    crypt('${infrastructure_admin_password}', gen_salt('bf', 12)),
    TRUE, FALSE, TRUE, FALSE, gen_random_uuid()
)
ON CONFLICT (username) DO NOTHING;

INSERT INTO auth.identity_role (identity_id, role_id)
SELECT identity.id, role.id
FROM auth.identity identity
JOIN auth.role role ON role.name = 'INFRASTRUCTURE_INTERNAL'
WHERE identity.username = '${infrastructure_admin_username}'
ON CONFLICT (identity_id, role_id) DO NOTHING;

-- The Next.js infrastructure portal is a public OAuth client: no secret is
-- stored in the browser and PKCE is mandatory.
INSERT INTO auth.oauth2_registered_client (
    id, client_id, client_id_issued_at, client_secret, client_name,
    client_authentication_methods, authorization_grant_types, redirect_uris,
    post_logout_redirect_uris, scopes, client_settings, token_settings
)
VALUES (
    gen_random_uuid()::text,
    'conecta-infrastructure-portal',
    CURRENT_TIMESTAMP,
    NULL,
    'Conecta Infrastructure Portal',
    'none',
    'authorization_code,refresh_token',
    'http://localhost:3000/infrastructure/clients',
    'http://localhost:3000/',
    'openid,profile,api.read',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":true}',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":false,"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.access-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.refresh-token-time-to-live":["java.time.Duration",28800.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]}'
)
ON CONFLICT (client_id) DO NOTHING;
