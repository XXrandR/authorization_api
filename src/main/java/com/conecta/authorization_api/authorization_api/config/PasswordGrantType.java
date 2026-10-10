package com.conecta.authorization_api.authorization_api.config;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public final class PasswordGrantType {

    private PasswordGrantType() {
    }

    public static final AuthorizationGrantType PASSWORD =
            new AuthorizationGrantType("password");
}
