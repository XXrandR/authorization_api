package com.conecta.authorization_api.authorization_api.config;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public class PasswordGrantAuthenticationConverter
        implements AuthenticationConverter {

    @Override
    public Authentication convert(
            HttpServletRequest request
    ) {

        String grantType =
                request.getParameter(
                        OAuth2ParameterNames.GRANT_TYPE
                );

        if (!PasswordGrantType.PASSWORD.getValue().equals(grantType)) {
            return null;
        }

        Authentication clientPrincipal =
                (Authentication) request.getUserPrincipal();

        if (!(clientPrincipal instanceof OAuth2ClientAuthenticationToken)) {
            throw new IllegalArgumentException(
                    "OAuth2 client authentication is required"
            );
        }

        String username =
                request.getParameter("username");

        String password =
                request.getParameter("password");

        if (!StringUtils.hasText(username)) {
            throw new IllegalArgumentException(
                    "username is required"
            );
        }

        if (!StringUtils.hasText(password)) {
            throw new IllegalArgumentException(
                    "password is required"
            );
        }

        String scope =
                request.getParameter(
                        OAuth2ParameterNames.SCOPE
                );

        Set<String> scopes =
                StringUtils.hasText(scope)
                        ? Arrays.stream(scope.split(" "))
                        .filter(StringUtils::hasText)
                        .collect(Collectors.toSet())
                        : Collections.emptySet();

        return new PasswordGrantAuthenticationToken(
                clientPrincipal,
                username,
                password,
                scopes
        );
    }
}
