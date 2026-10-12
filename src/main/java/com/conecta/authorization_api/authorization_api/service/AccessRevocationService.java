package com.conecta.authorization_api.authorization_api.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class AccessRevocationService {
    private final JdbcTemplate jdbc;
    private final SessionRegistry sessions;

    public AccessRevocationService(JdbcTemplate jdbc, SessionRegistry sessions) {
        this.jdbc = jdbc;
        this.sessions = sessions;
    }

    public void revokeUser(String username) {
        jdbc.update("DELETE FROM auth.oauth2_authorization WHERE principal_name = ?", username);
        for (Object principal : sessions.getAllPrincipals()) {
            if (principal instanceof UserDetails user && user.getUsername().equals(username)) {
                sessions.getAllSessions(principal, false).forEach(session -> session.expireNow());
            }
        }
    }
}
