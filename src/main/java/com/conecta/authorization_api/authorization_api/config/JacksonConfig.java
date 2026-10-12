package com.conecta.authorization_api.authorization_api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
public class JacksonConfig {
    @Bean
    public ObjectMapper objectMapper() { // Returns JsonMapper (which extends ObjectMapper)
        return new ObjectMapper();
    }
}
