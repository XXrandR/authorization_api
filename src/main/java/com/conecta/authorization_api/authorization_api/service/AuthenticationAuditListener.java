package com.conecta.authorization_api.authorization_api.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class AuthenticationAuditListener {
    private static final Logger log = LoggerFactory.getLogger(AuthenticationAuditListener.class);
    private final JdbcTemplate jdbcTemplate;

    public AuthenticationAuditListener(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        if (!(event.getAuthentication() instanceof org.springframework.security.authentication.UsernamePasswordAuthenticationToken)) return;
        String username = event.getAuthentication().getName();
        log.info("Authentication succeeded for username={}", username);
        jdbcTemplate.update("""
                INSERT INTO auth.access_event (id, username, event_type)
                VALUES (?, ?, 'LOGIN_SUCCEEDED')
                """, UUID.randomUUID(), username);
    }

    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        String username = event.getAuthentication().getName();
        log.warn("Authentication failed for username={}", username);
        jdbcTemplate.update("""
                INSERT INTO auth.access_event (id, username, event_type)
                VALUES (?, ?, 'LOGIN_FAILED')
                """, UUID.randomUUID(), username);
    }

    @EventListener
    public void onLogout(org.springframework.security.authentication.event.LogoutSuccessEvent event) {
        jdbcTemplate.update("INSERT INTO auth.access_event (id, username, event_type) VALUES (?, ?, 'LOGOUT')",
                UUID.randomUUID(), event.getAuthentication().getName());
    }
}
