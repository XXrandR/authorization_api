package com.conecta.authorization_api.authorization_api.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class AuditService {
    private final JdbcTemplate jdbcTemplate;

    public AuditService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void record(String action, String targetType, String targetId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String actor = authentication == null ? "SYSTEM" : authentication.getName();
        jdbcTemplate.update("""
                INSERT INTO auth.audit_event (id, actor_username, action, target_type, target_id, correlation_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """, UUID.randomUUID(), actor, action, targetType, targetId, org.slf4j.MDC.get("requestId"));
    }
}
