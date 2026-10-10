package com.conecta.authorization_api.authorization_api.service;

import com.conecta.authorization_api.authorization_api.domain.Identity;
import com.conecta.authorization_api.authorization_api.repository.IdentityRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class IdentityUserDetailsService
        implements UserDetailsService {

    private final IdentityRepository repository;

    public IdentityUserDetailsService(
            IdentityRepository repository
    ) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(
            String username
    ) throws UsernameNotFoundException {

        Identity identity =
                repository.findByUsername(username)
                        .orElseThrow(() ->
                                new UsernameNotFoundException(
                                        "User not found"
                                )
                        );

        return User.builder()
                .username(identity.getUsername())
                .password(identity.getPasswordHash())
                .authorities(
                        identity.getRoles()
                                .stream()
                                .map(role ->
                                        new SimpleGrantedAuthority(
                                                role.getName()
                                        )
                                )
                                .toList()
                )
                .disabled(!identity.isActive())
                .accountLocked(identity.isBlocked())
                .build();
    }
}
