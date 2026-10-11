package com.conecta.authorization_api.authorization_api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class AuthorizationApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationApiApplication.class, args);
    }

}
