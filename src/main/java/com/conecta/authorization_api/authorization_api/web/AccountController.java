package com.conecta.authorization_api.authorization_api.web;

import com.conecta.authorization_api.authorization_api.service.AccountService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/accounts")
public class AccountController {
    private final AccountService accounts;

    public AccountController(AccountService accounts) {
        this.accounts = accounts;
    }

    @PostMapping("/registrations")
    @ResponseStatus(HttpStatus.ACCEPTED)
    void register(@Valid @RequestBody RegistrationRequest request) {
        accounts.register(request.username(), request.email(), request.password(), request.invitationToken());
    }

    @PostMapping("/email-verifications")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void verifyEmail(@Valid @RequestBody TokenRequest request) {
        accounts.verifyEmail(request.token());
    }

    @PostMapping("/password-resets")
    @ResponseStatus(HttpStatus.ACCEPTED)
    void requestPasswordReset(@Valid @RequestBody PasswordResetRequest request) {
        accounts.requestPasswordReset(request.email());
    }

    @PostMapping("/email-verifications/resend")
    @ResponseStatus(HttpStatus.ACCEPTED)
    void resendVerification(@Valid @RequestBody PasswordResetRequest request) { accounts.resendVerification(request.email()); }

    @PostMapping("/password-resets/confirm")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void resetPassword(@Valid @RequestBody PasswordResetConfirmationRequest request) {
        accounts.resetPassword(request.token(), request.password());
    }

    record RegistrationRequest(
            @NotBlank @Pattern(regexp = "^[a-zA-Z0-9._-]{3,50}$") String username,
            @NotBlank @Email @Size(max = 255) String email,
            @NotBlank @Size(min = 12, max = 72) String password,
            String invitationToken) {
    }

    record TokenRequest(@NotBlank String token) {
    }

    record PasswordResetRequest(@NotBlank @Email @Size(max = 255) String email) {
    }

    record PasswordResetConfirmationRequest(
            @NotBlank String token,
            @NotBlank @Size(min = 12, max = 72) String password) {
    }
}
