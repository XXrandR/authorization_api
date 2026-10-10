package com.conecta.authorization_api.authorization_api.config;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Set;

@Getter
public class PasswordGrantAuthenticationToken
        extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String username;
    private final String password;
    private final Set<String> scopes;

    public PasswordGrantAuthenticationToken(
            Authentication clientPrincipal,
            String username,
            String password,
            Set<String> scopes
    ) {
        super(
                PasswordGrantType.PASSWORD,
                clientPrincipal,
                null
        );

        this.username = username;
        this.password = password;
        this.scopes = scopes;
    }

    public Authentication getClientPrincipal() {
        return (Authentication) getPrincipal();
    }
}
