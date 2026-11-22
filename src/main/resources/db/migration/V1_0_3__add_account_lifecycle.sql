INSERT INTO auth.role (id, role_name)
VALUES (gen_random_uuid(), 'USER')
ON CONFLICT (role_name) DO NOTHING;

CREATE TABLE auth.verification_token (
    id UUID PRIMARY KEY,
    identity_id UUID NOT NULL REFERENCES auth.identity (id) ON DELETE CASCADE,
    token_type VARCHAR(32) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp,
    CONSTRAINT chk_verification_token_type CHECK (
        token_type IN ('EMAIL_VERIFICATION', 'PASSWORD_RESET')
    )
);

CREATE INDEX idx_verification_token_identity_type
ON auth.verification_token (identity_id, token_type)
WHERE consumed_at IS NULL;
