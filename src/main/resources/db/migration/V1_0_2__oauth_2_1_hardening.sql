-- OAuth 2.1 removes the resource-owner password grant. The old development
-- identity/client are intentionally removed rather than becoming credentials
-- that silently exist in every environment.
DELETE FROM auth.oauth2_authorization_consent
WHERE registered_client_id IN (
    SELECT id FROM auth.oauth2_registered_client WHERE client_id = 'example-client'
);

DELETE FROM auth.oauth2_authorization
WHERE registered_client_id IN (
    SELECT id FROM auth.oauth2_registered_client WHERE client_id = 'example-client'
);

DELETE FROM auth.oauth2_registered_client WHERE client_id = 'example-client';
DELETE FROM auth.identity WHERE username = 'admin' AND email = 'admin@example.local';

-- OAuth identity providers may omit issuer. PostgreSQL's ordinary UNIQUE
-- constraint considers NULL values distinct, which would permit duplicates.
ALTER TABLE auth.external_identity
    DROP CONSTRAINT uq_external_identity_provider_subject;

CREATE UNIQUE INDEX uq_external_identity_provider_subject
    ON auth.external_identity (provider, issuer, provider_subject) NULLS NOT DISTINCT;

-- JDBC authorization lookups use state and token values. These indexes keep
-- revocation and authorization-code exchange from degrading as data grows.
CREATE INDEX idx_oauth2_authorization_state
    ON auth.oauth2_authorization (state)
    WHERE state IS NOT NULL;

CREATE INDEX idx_oauth2_authorization_authorization_code
    ON auth.oauth2_authorization (authorization_code_value)
    WHERE authorization_code_value IS NOT NULL;

CREATE INDEX idx_oauth2_authorization_refresh_token
    ON auth.oauth2_authorization (refresh_token_value)
    WHERE refresh_token_value IS NOT NULL;
