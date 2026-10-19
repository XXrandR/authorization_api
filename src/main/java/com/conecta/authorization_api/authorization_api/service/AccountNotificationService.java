package com.conecta.authorization_api.authorization_api.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class AccountNotificationService {
    private final ObjectProvider<JavaMailSender> mailSender;
    private final String webBaseUrl;

    public AccountNotificationService(
            ObjectProvider<JavaMailSender> mailSender,
            @Value("${app.accounts.web-base-url:http://localhost:3000}") String webBaseUrl) {
        this.mailSender = mailSender;
        this.webBaseUrl = webBaseUrl.replaceAll("/$", "");
    }

    public void sendEmailVerification(String email, String rawToken) {
		log.info("The token to: {} is {}",email, rawToken);
        send(email, "Verify your New account",
                "Verify your email: " + webBaseUrl + "/verify-email?token=" + rawToken);
    }

    public void sendPasswordReset(String email, String rawToken) {
        send(email, "Reset your New password",
                "Reset your password: " + webBaseUrl + "/reset-password?token=" + rawToken);
    }

    public void sendInvitation(String email, String rawToken) {
        send(email, "You are invited to New",
                "Create your account: " + webBaseUrl + "/register?invitation=" + rawToken);
    }

    private void send(String recipient, String subject, String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(recipient);
        message.setSubject(subject);
        message.setText(text);
        JavaMailSender sender = mailSender.getIfAvailable();
        if (sender == null) {
            throw new IllegalStateException("SMTP delivery is not configured");
        }
        sender.send(message);
    }
}
