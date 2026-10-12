package com.conecta.authorization_api.authorization_api.web;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/session")
public class SessionController {
    @GetMapping
    SessionView current(Authentication authentication) {
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return new SessionView(false, null, List.of());
        }
        return new SessionView(true, authentication.getName(), authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority()).sorted().toList());
    }

    record SessionView(boolean authenticated, String username, List<String> roles) {
    }
}
