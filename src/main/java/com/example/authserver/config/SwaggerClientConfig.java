package com.example.authserver.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

@Configuration
public class SwaggerClientConfig {

    private static final Logger logger = LoggerFactory.getLogger(SwaggerClientConfig.class);

    @Bean
    public CommandLineRunner initSwaggerClient(RegisteredClientRepository clientRepository) {
        return args -> {
            // Check if swagger client already exists to avoid duplicates
            try {
                RegisteredClient existingClient = clientRepository.findByClientId("swagger-ui");
                if (existingClient != null) {
                    logger.info("Swagger UI OAuth2 client already exists [clientId=swagger-ui]");
                    return;
                }
            } catch (Exception e) {
                logger.debug("Swagger UI client not found, will create new one [error={}]", e.getMessage());
            }

            // Create PKCE-enabled public client for Swagger UI
            RegisteredClient swaggerClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("swagger-ui")
                // No client secret for PKCE public client
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // Public client
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:9000/swagger-ui/oauth2-redirect.html")
                .redirectUri("http://localhost:9000/webjars/swagger-ui/oauth2-redirect.html")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .scope("write")
                .scope("user:create")
                .scope("user:lock")
                .scope("user:unlock")
                .scope("user:read")
                .scope("user:update")
                .scope("user:delete")
                .clientSettings(ClientSettings.builder()
                    .requireAuthorizationConsent(false) // Skip consent for demo purposes
                    .requireProofKey(true) // Enable PKCE requirement
                    .build())
                .build();

            clientRepository.save(swaggerClient);
            logger.info("Created PKCE-enabled Swagger UI OAuth2 client [clientId=swagger-ui]");
        };
    }
}