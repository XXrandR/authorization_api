package com.conecta.authorization_api.authorization_api.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/** Read-only, allow-listed projections. Never selects passwords, secrets, or tokens. */
@Service
public class AdminQueryService {
    private final JdbcTemplate jdbc;

    public AdminQueryService(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public Result page(String resource, String query, int page, int size) {
        if (page < 0 || size < 1 || size > 100) throw new IllegalArgumentException("Invalid page or size");
        String projection = switch (resource) {
            case "identities" -> """
                    SELECT i.id, i.username, i.email, i.is_active AS active, i.is_blocked AS blocked,
                    coalesce(string_agg(r.name, ',' ORDER BY r.name), '') AS roles FROM auth.identity i
                    LEFT JOIN auth.identity_role ir ON ir.identity_id = i.id LEFT JOIN auth.role r ON r.id = ir.role_id
                    GROUP BY i.id
                    """;
            case "roles" -> """
                    SELECT r.id, r.name, r.is_system AS system, count(ir.identity_id) AS members FROM auth.role r
                    LEFT JOIN auth.identity_role ir ON ir.role_id = r.id GROUP BY r.id
                    """;
            case "invitations" -> "SELECT id,email,role_names,expires_at,accepted_at,revoked_at,created_at FROM auth.invitation";
            case "authorizations" -> """
                    SELECT a.id,a.principal_name,c.client_id,a.authorization_grant_type,a.authorized_scopes,
                    a.access_token_expires_at,a.refresh_token_expires_at FROM auth.oauth2_authorization a
                    JOIN auth.oauth2_registered_client c ON c.id = a.registered_client_id
                    """;
            case "audit-events" -> "SELECT id,actor_username,action,target_type,target_id,created_at FROM auth.audit_event";
            case "access-events" -> "SELECT id,username,event_type,remote_address,user_agent,created_at FROM auth.access_event";
            default -> throw new IllegalArgumentException("Unknown resource");
        };
        String base = "WITH records AS (" + projection + ") SELECT * FROM records WHERE lower(records::text) LIKE ?";
        String filter = "%" + query.toLowerCase(java.util.Locale.ROOT) + "%";
        Long total = jdbc.queryForObject("SELECT count(*) FROM (" + base + ") matches", Long.class, filter);
        List<Map<String, Object>> items = jdbc.queryForList(base + " ORDER BY id LIMIT ? OFFSET ?", filter, size, (long) page * size);
        return new Result(items, total == null ? 0 : total, page, size);
    }

    public record Result(List<Map<String, Object>> items, long total, int page, int size) { }
}
