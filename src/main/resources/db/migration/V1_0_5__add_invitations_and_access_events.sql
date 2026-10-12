CREATE TABLE auth.invitation (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    role_names VARCHAR(1000) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_invitation_email ON auth.invitation (email, created_at DESC);

CREATE TABLE auth.access_event (
    id UUID PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    remote_address VARCHAR(64),
    user_agent VARCHAR(1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_access_event_username_created_at ON auth.access_event (username, created_at DESC);
