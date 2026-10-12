package com.conecta.authorization_api.authorization_api.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
public class InfrastructureClientService {
    private final RegisteredClientRepository clients;
    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;
    private final AuditService audit;

    public InfrastructureClientService(RegisteredClientRepository clients, JdbcTemplate jdbcTemplate,
                                       PasswordEncoder passwordEncoder, AuditService audit) {
        this.clients = new JdbcRegisteredClientRepository(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
        this.passwordEncoder = passwordEncoder;
        this.audit = audit;
    }

    public List<ClientSummary> list() {
        return jdbcTemplate.query("""
                SELECT client_id, client_name, authorization_grant_types, scopes, redirect_uris
                FROM auth.oauth2_registered_client ORDER BY client_id
                """, (row, index) -> new ClientSummary(row.getString(1), row.getString(2), row.getString(3), row.getString(4), row.getString(5)));
    }

    @Transactional
    public ClientCredential create(ClientSpec spec) {
        validate(spec);
        if (clients.findByClientId(spec.clientId()) != null) throw new IllegalStateException("Client ID already exists");
        String secret = spec.publicClient() ? null : newSecret();
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(spec.clientId())
                .clientIdIssuedAt(Instant.now())
                .clientName(spec.clientName())
                .clientSettings(ClientSettings.builder().requireProofKey(!spec.machine()).requireAuthorizationConsent(!spec.machine()).build())
                .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build());
        if (spec.machine()) builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
        else builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        spec.redirectUris().forEach(builder::redirectUri);
        spec.scopes().forEach(builder::scope);
        if (secret == null) builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        else builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).clientSecret(passwordEncoder.encode(secret));
        clients.save(builder.build());
        audit.record("CLIENT_CREATED", "OAUTH_CLIENT", spec.clientId());
        return new ClientCredential(spec.clientId(), secret);
    }

    public ClientDetail detail(String clientId) {
        RegisteredClient client = required(clientId);
        Boolean enabled = jdbcTemplate.queryForObject("SELECT enabled FROM auth.oauth2_registered_client WHERE client_id = ?", Boolean.class, clientId);
        Long authorizations = jdbcTemplate.queryForObject("SELECT count(*) FROM auth.oauth2_authorization WHERE registered_client_id = ?", Long.class, client.getId());
        return new ClientDetail(client.getClientId(), client.getClientName(), client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE),
                client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS), client.getRedirectUris().stream().sorted().toList(),
                client.getScopes().stream().sorted().toList(), Boolean.TRUE.equals(enabled), client.getClientSettings().isRequireProofKey(),
                client.getClientSettings().isRequireAuthorizationConsent(), client.getClientSecretExpiresAt(), authorizations == null ? 0 : authorizations);
    }

    public ClientPage page(String query, int page, int size) {
        if (page < 0 || size < 1 || size > 100) throw new IllegalArgumentException("Invalid page or size");
        String filter = "%" + query.toLowerCase(java.util.Locale.ROOT) + "%";
        Long count = jdbcTemplate.queryForObject("SELECT count(*) FROM auth.oauth2_registered_client WHERE lower(client_id || ' ' || client_name) LIKE ?", Long.class, filter);
        List<ClientDetail> items = jdbcTemplate.queryForList("SELECT client_id FROM auth.oauth2_registered_client WHERE lower(client_id || ' ' || client_name) LIKE ? ORDER BY client_id LIMIT ? OFFSET ?", String.class, filter, size, (long) page * size).stream().map(this::detail).toList();
        return new ClientPage(items, count == null ? 0 : count, page, size);
    }

    @Transactional
    public void update(String clientId, ClientSpec spec, boolean enabled) {
        validate(spec);
        ClientDetail before = detail(clientId);
        if (!spec.clientId().equals(clientId) || spec.publicClient() != before.publicClient() || spec.machine() != before.machine()) {
            throw new IllegalArgumentException("Client ID and type are immutable; create a new client to change them");
        }
        clients.save(RegisteredClient.from(required(clientId)).clientName(spec.clientName())
                .redirectUris(uris -> { uris.clear(); uris.addAll(spec.redirectUris()); })
                .scopes(scopes -> { scopes.clear(); scopes.addAll(spec.scopes()); }).build());
        jdbcTemplate.update("UPDATE auth.oauth2_registered_client SET enabled = ? WHERE client_id = ?", enabled, clientId);
        revoke(clientId);
        audit.record("CLIENT_UPDATED", "OAUTH_CLIENT", clientId);
    }

    @Transactional
    public void revoke(String clientId) {
        jdbcTemplate.update("DELETE FROM auth.oauth2_authorization WHERE registered_client_id = ?", required(clientId).getId());
        audit.record("CLIENT_AUTHORIZATIONS_REVOKED", "OAUTH_CLIENT", clientId);
    }

    private void validate(ClientSpec spec) {
        if (spec.machine() && spec.publicClient()) throw new IllegalArgumentException("Machine clients must be confidential");
        if (!spec.machine() && spec.redirectUris().isEmpty()) throw new IllegalArgumentException("Interactive clients require redirect URIs");
        if (spec.machine() && (!spec.redirectUris().isEmpty() || spec.scopes().contains("openid"))) throw new IllegalArgumentException("Machine clients cannot have redirect URIs or openid scope");
        for (String value : spec.redirectUris()) {
            java.net.URI uri;
            try { uri = java.net.URI.create(value); } catch (IllegalArgumentException error) { throw new IllegalArgumentException("Invalid redirect URI"); }
            String host = uri.getHost();
            boolean loopback = "localhost".equals(host) || "127.0.0.1".equals(host) || "[::1]".equals(host);
            if (uri.getFragment() != null || uri.getUserInfo() != null || host == null || value.contains("*")
                    || !("https".equals(uri.getScheme()) || (loopback && "http".equals(uri.getScheme())))) {
                throw new IllegalArgumentException("Use an exact HTTPS redirect URI, or HTTP loopback for local development");
            }
        }
    }

    @Transactional
    public ClientCredential rotateSecret(String clientId) {
        RegisteredClient existing = required(clientId);
        if (existing.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            throw new IllegalArgumentException("Public clients do not have secrets; use PKCE");
        }
        String secret = newSecret();
        clients.save(RegisteredClient.from(existing).clientSecret(passwordEncoder.encode(secret)).clientSecretExpiresAt(null).build());
        audit.record("CLIENT_SECRET_ROTATED", "OAUTH_CLIENT", clientId);
        return new ClientCredential(clientId, secret);
    }

    @Transactional
    public void delete(String clientId) {
        RegisteredClient client = required(clientId);
        jdbcTemplate.update("DELETE FROM auth.oauth2_authorization_consent WHERE registered_client_id = ?", client.getId());
        jdbcTemplate.update("DELETE FROM auth.oauth2_authorization WHERE registered_client_id = ?", client.getId());
        jdbcTemplate.update("DELETE FROM auth.oauth2_registered_client WHERE id = ?", client.getId());
        audit.record("CLIENT_DELETED", "OAUTH_CLIENT", clientId);
    }

    private RegisteredClient required(String clientId) {
        RegisteredClient client = clients.findByClientId(clientId);
        if (client == null) throw new IllegalArgumentException("Unknown OAuth client");
        return client;
    }

    private static String newSecret() {
        byte[] bytes = new byte[48];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public record ClientSpec(String clientId, String clientName, boolean publicClient, List<String> redirectUris, List<String> scopes, boolean machine) {}
    public record ClientDetail(String clientId, String clientName, boolean publicClient, boolean machine, List<String> redirectUris,
                               List<String> scopes, boolean enabled, boolean requireProofKey, boolean requireConsent, Instant secretExpiresAt, long authorizationCount) { }
    public record ClientPage(List<ClientDetail> items, long total, int page, int size) { }
    public record ClientSummary(String clientId, String clientName, String grantTypes, String scopes, String redirectUris) {}
    public record ClientCredential(String clientId, String clientSecret) {}
}
