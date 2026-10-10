package com.conecta.authorization_api.authorization_api.config;

import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Set;

public class PasswordGrantAuthenticationProvider
        implements AuthenticationProvider {

    private final AuthenticationProvider userAuthenticationProvider;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    public PasswordGrantAuthenticationProvider(
            AuthenticationProvider userAuthenticationProvider,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator
    ) {
        this.userAuthenticationProvider =
                userAuthenticationProvider;

        this.authorizationService =
                authorizationService;

        this.tokenGenerator =
                tokenGenerator;
    }

    @Override
    public Authentication authenticate(
            Authentication authentication
    ) {

        PasswordGrantAuthenticationToken grant =
                (PasswordGrantAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal =
                (OAuth2ClientAuthenticationToken)
                        grant.getClientPrincipal();

        RegisteredClient registeredClient = getRegisteredClient(clientPrincipal);

        /*
         * Authenticate:
         *
         * admin / 1234
         */
        Authentication userAuthentication =
                userAuthenticationProvider.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                grant.getUsername(),
                                grant.getPassword()
                        )
                );

        /*
         * Determine scopes.
         */
        Set<String> authorizedScopes =
                grant.getScopes().isEmpty()
                        ? registeredClient.getScopes()
                        : grant.getScopes();

        /*
         * Make sure requested scopes are actually
         * allowed for the client.
         */
        if (!registeredClient.getScopes()
                .containsAll(authorizedScopes)) {

            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_SCOPE,
                            "Requested scope is not allowed",
                            null
                    )
            );
        }

        /*
         * Build token context.
         */
        DefaultOAuth2TokenContext.Builder tokenContextBuilder =
                DefaultOAuth2TokenContext.builder()
                        .registeredClient(registeredClient)
                        .principal(userAuthentication)
                        .authorizationServerContext(
                                AuthorizationServerContextHolder
                                        .getContext()
                        )
                        .authorizedScopes(authorizedScopes)
                        .authorizationGrantType(
                                PasswordGrantType.PASSWORD
                        )
                        .authorizationGrant(grant);

        /*
         * Generate access token.
         */
        OAuth2TokenContext accessTokenContext =
                tokenContextBuilder
                        .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                        .build();

        OAuth2Token generatedAccessToken =
                tokenGenerator.generate(
                        accessTokenContext
                );

        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.SERVER_ERROR,
                            "Failed to generate access token",
                            null
                    )
            );
        }

        OAuth2AccessToken accessToken;

        if (generatedAccessToken instanceof Jwt jwt) {

            accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    jwt.getTokenValue(),
                    jwt.getIssuedAt(),
                    jwt.getExpiresAt(),
                    authorizedScopes
            );

        } else if (generatedAccessToken instanceof OAuth2AccessToken token) {

            accessToken = token;

        } else {

            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.SERVER_ERROR,
                            "Unsupported access token type: "
                                    + generatedAccessToken.getClass().getName(),
                            null
                    )
            );
        }

        /*
         * Create authorization.
         */
        OAuth2Authorization.Builder authorization =
                OAuth2Authorization.withRegisteredClient(
                                registeredClient
                        )
                        .principalName(
                                userAuthentication.getName()
                        )
                        .authorizationGrantType(
                                PasswordGrantType.PASSWORD
                        )
                        .authorizedScopes(
                                authorizedScopes
                        );

        authorization.accessToken(accessToken);

        /*
         * Save authorization in:
         *
         * auth.oauth2_authorization
         */
        OAuth2Authorization savedAuthorization =
                authorization.build();

        authorizationService.save(
                savedAuthorization
        );

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                clientPrincipal,
                accessToken
        );
    }

    private static @NonNull RegisteredClient getRegisteredClient(OAuth2ClientAuthenticationToken clientPrincipal) {
        RegisteredClient registeredClient =
                clientPrincipal.getRegisteredClient();

        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_CLIENT
                    )
            );
        }

        /*
         * Validate that this client is allowed to use
         * the password grant.
         */
        if (!registeredClient.getAuthorizationGrantTypes()
                .contains(PasswordGrantType.PASSWORD)) {

            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
                            "Client is not authorized for password grant",
                            null
                    )
            );
        }
        return registeredClient;
    }

    @Override
    public boolean supports(
            Class<?> authentication
    ) {

        return PasswordGrantAuthenticationToken.class
                .isAssignableFrom(authentication);
    }
}
