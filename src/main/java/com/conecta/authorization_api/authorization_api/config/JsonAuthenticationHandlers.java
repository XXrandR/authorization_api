package com.conecta.authorization_api.authorization_api.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
public class JsonAuthenticationHandlers {
    private final ObjectMapper objectMapper;
    private final RequestCache requestCache;

    public JsonAuthenticationHandlers(ObjectMapper objectMapper, RequestCache requestCache) {
        this.objectMapper = objectMapper;
        this.requestCache = requestCache;
    }

    public AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> write(response, HttpServletResponse.SC_OK,
                Map.of("authenticated", true, "redirectUrl", savedRequestUrl(request, response)));
    }

    public AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) -> write(response, HttpServletResponse.SC_UNAUTHORIZED,
                Map.of("authenticated", false, "message", "Invalid username or password"));
    }

    private String savedRequestUrl(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        requestCache.removeRequest(request, response);
        if (savedRequest != null && savedRequest.getRedirectUrl().contains("/oauth2/authorize")) {
            return savedRequest.getRedirectUrl();
        }
        Authentication authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("INFRASTRUCTURE_INTERNAL")) ? "/admin" : "/";
    }

    private void write(HttpServletResponse response, int status, Map<String, Object> body) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
