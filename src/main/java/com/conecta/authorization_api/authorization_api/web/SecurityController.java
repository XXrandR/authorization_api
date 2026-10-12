package com.conecta.authorization_api.authorization_api.web;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/security")
public class SecurityController {

    @GetMapping("/csrf")
    CsrfResponse csrf(CsrfToken token) {
        return new CsrfResponse(token.getHeaderName(), token.getToken());
    }

    record CsrfResponse(String headerName, String token) {
    }
}
