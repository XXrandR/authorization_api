# Account API contract

These endpoints power the same-origin identity web application. Every JSON
`POST` first obtains a CSRF token from `GET /api/v1/security/csrf`, retains the
`XSRF-TOKEN` cookie, and sends the returned token in its declared header
(currently `X-XSRF-TOKEN`).

## Public endpoints

| Endpoint | Body | Success | Behaviour |
| --- | --- | --- | --- |
| `POST /api/v1/accounts/registrations` | `username`, `email`, `password` | `202` | Creates an inactive `USER` account and sends an email verification link. Password minimum: 12 chars. |
| `POST /api/v1/accounts/email-verifications` | `token` | `204` | Consumes a one-time email token and activates the account. |
| `POST /api/v1/accounts/password-resets` | `email` | `202` | Sends a reset link when the address exists. Response intentionally does not reveal account existence. |
| `POST /api/v1/accounts/password-resets/confirm` | `token`, `password` | `204` | Consumes a one-time reset token and updates the password. |

Verification links expire after 24 hours; reset links expire after one hour.
Raw tokens appear only in the email and are never stored in the database. The
database stores a SHA-256 hash and consumed tokens cannot be reused.

## SMTP requirement

Configure Spring Mail in every environment where registration/reset is enabled:

```properties
spring.mail.host=smtp.example.com
spring.mail.port=587
spring.mail.username=...
spring.mail.password=...
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
app.accounts.web-base-url=https://auth.example.com
```

If no `JavaMailSender` is configured, account creation and reset requests fail
closed rather than creating a user who cannot verify their account.

## Browser login

`POST /login` is Spring Security form login, not a JSON API. The identity web
app fetches a CSRF token and sends URL-encoded `username` and `password` with
browser cookies. It may use either username or email. After login, Spring
Security resumes the saved OAuth authorization request.
