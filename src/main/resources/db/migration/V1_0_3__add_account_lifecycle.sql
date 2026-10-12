INSERT INTO auth.role (id, name)
VALUES (gen_random_uuid(), 'USER')
ON CONFLICT (name) DO NOTHING;

CREATE TABLE auth.verification_token (
    id UUID PRIMARY KEY,
    identity_id UUID NOT NULL REFERENCES auth.identity(id) ON DELETE CASCADE,
    type VARCHAR(32) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_verification_token_type CHECK (type IN ('EMAIL_VERIFICATION', 'PASSWORD_RESET'))
);

CREATE INDEX idx_verification_token_identity_type
    ON auth.verification_token (identity_id, type)
    WHERE consumed_at IS NULL;
