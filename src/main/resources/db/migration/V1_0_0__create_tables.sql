CREATE SCHEMA IF NOT EXISTS auth;

-- IDENTITY
CREATE TABLE auth.identity (
    id UUID PRIMARY KEY,

    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(20),
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    phone_verified BOOLEAN NOT NULL DEFAULT FALSE,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    person_id UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ
);


CREATE TABLE auth.role (
    id UUID PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE auth.identity_role (
    identity_id UUID NOT NULL,
    role_id UUID NOT NULL,

    PRIMARY KEY (identity_id, role_id),

    CONSTRAINT fk_identity_role_identity
        FOREIGN KEY (identity_id)
        REFERENCES auth.identity(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_identity_role_role
        FOREIGN KEY (role_id)
        REFERENCES auth.role(id)
        ON DELETE CASCADE
);


-- Google / Microsoft / Facebook / Apple / GitHub / etc.
CREATE TABLE auth.external_identity (
    id UUID PRIMARY KEY,

    identity_id UUID NOT NULL,
    provider VARCHAR(30) NOT NULL,
    issuer VARCHAR(500),
    provider_subject VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255),

    email VARCHAR(255),
    email_verified BOOLEAN,

    name VARCHAR(255),
    given_name VARCHAR(255),
    family_name VARCHAR(255),
    picture_url VARCHAR(1000),
    profile_url VARCHAR(1000),
    preferred_username VARCHAR(255),
    locale VARCHAR(20),
    hosted_domain VARCHAR(255),
    metadata JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,

    CONSTRAINT fk_external_identity_identity
        FOREIGN KEY (identity_id)
        REFERENCES auth.identity(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_external_identity_provider_subject
        UNIQUE (provider, issuer, provider_subject)
);


-- OAUTH2 REGISTERED CLIENTS
-- Required by JdbcRegisteredClientRepository
CREATE TABLE auth.oauth2_registered_client (
    id VARCHAR(255) PRIMARY KEY,

    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_id_issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_secret VARCHAR(255),
    client_secret_expires_at TIMESTAMPTZ,
    client_name VARCHAR(255) NOT NULL,
    client_authentication_methods VARCHAR(1000) NOT NULL,

    authorization_grant_types VARCHAR(1000) NOT NULL,

    redirect_uris VARCHAR(1000),
    post_logout_redirect_uris VARCHAR(1000),
    scopes VARCHAR(1000) NOT NULL,
    client_settings VARCHAR(2000) NOT NULL,
    token_settings VARCHAR(2000) NOT NULL
);


-- OAUTH2 AUTHORIZATIONS / TOKENS
-- Required by JdbcOAuth2AuthorizationService
CREATE TABLE auth.oauth2_authorization (
    id VARCHAR(255) PRIMARY KEY,

    registered_client_id VARCHAR(255) NOT NULL,
    principal_name VARCHAR(255) NOT NULL,
    authorization_grant_type VARCHAR(255) NOT NULL,
    authorized_scopes VARCHAR(1000),

    attributes VARCHAR(4000),
    state VARCHAR(500),

    authorization_code_value VARCHAR(4000),
    authorization_code_issued_at TIMESTAMPTZ,
    authorization_code_expires_at TIMESTAMPTZ,
    authorization_code_metadata VARCHAR(2000),

    access_token_value VARCHAR(4000),
    access_token_issued_at TIMESTAMPTZ,
    access_token_expires_at TIMESTAMPTZ,
    access_token_metadata VARCHAR(2000),
    access_token_type VARCHAR(255),
    access_token_scopes VARCHAR(1000),

    refresh_token_value VARCHAR(4000),
    refresh_token_issued_at TIMESTAMPTZ,
    refresh_token_expires_at TIMESTAMPTZ,
    refresh_token_metadata VARCHAR(2000),

    oidc_id_token_value VARCHAR(4000),
    oidc_id_token_issued_at TIMESTAMPTZ,
    oidc_id_token_expires_at TIMESTAMPTZ,
    oidc_id_token_metadata VARCHAR(2000),
    oidc_id_token_claims VARCHAR(2000),

    user_code_value VARCHAR(4000),
    user_code_issued_at TIMESTAMPTZ,
    user_code_expires_at TIMESTAMPTZ,
    user_code_metadata VARCHAR(2000),

    device_code_value VARCHAR(4000),
    device_code_issued_at TIMESTAMPTZ,
    device_code_expires_at TIMESTAMPTZ,
    device_code_metadata VARCHAR(2000)
);


-- OAUTH2 CONSENT
-- Required by JdbcOAuth2AuthorizationConsentService
CREATE TABLE auth.oauth2_authorization_consent (
    registered_client_id VARCHAR(255) NOT NULL,
    principal_name VARCHAR(255) NOT NULL,
    authorities VARCHAR(1000) NOT NULL,
    PRIMARY KEY (
        registered_client_id,
        principal_name
    )
);

