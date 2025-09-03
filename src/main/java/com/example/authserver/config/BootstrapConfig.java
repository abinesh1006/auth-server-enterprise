package com.example.authserver.config;

import com.example.authserver.client.ClientRegistrationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class BootstrapConfig {

    private static final Logger logger = LoggerFactory.getLogger(BootstrapConfig.class);

    @Bean
    public CommandLineRunner createBootstrapClient(RegisteredClientRepository clientRepository,
                                                   org.springframework.security.crypto.password.PasswordEncoder passwordEncoder) {
        return args -> {
            String bootstrapClientId = "bootstrap-client";
            String plainSecret = "bootstrap-secret";
            
            // Check if bootstrap client already exists
            try {
                RegisteredClient existingClient = clientRepository.findByClientId(bootstrapClientId);
                if (existingClient != null) {
                    logger.info("Bootstrap client already exists: {}", bootstrapClientId);
                    return;
                }
            } catch (Exception e) {
                // Client doesn't exist, continue with creation
            }

            // Create token settings with proper durations
            TokenSettings tokenSettings = TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofHours(1))
                    .refreshTokenTimeToLive(Duration.ofDays(30))
                    .reuseRefreshTokens(true)
                    .build();

            // Create client settings
            ClientSettings clientSettings = ClientSettings.builder()
                    .requireProofKey(false)
                    .requireAuthorizationConsent(false)
                    .build();

            // Create bootstrap client with properly encoded secret
            RegisteredClient bootstrapClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(bootstrapClientId)
                    .clientSecret(passwordEncoder.encode(plainSecret))  // Properly encode with BCrypt
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(new AuthorizationGrantType("password"))  // Add password grant type
                    .redirectUri("http://localhost:8081/login/oauth2/code/bootstrap-client")
                    .redirectUri("https://oauth.pstmn.io/v1/callback")  // For Postman testing
                    .scope("read")
                    .scope("write")
                    .scope("user:create")
                    .scope("user:lock")
                    .scope("user:unlock")
                    .tokenSettings(tokenSettings)
                    .clientSettings(clientSettings)
                    .build();

            clientRepository.save(bootstrapClient);
            
            logger.info("=".repeat(80));
            logger.info("BOOTSTRAP CLIENT CREATED SUCCESSFULLY!");
            logger.info("Client ID: {}", bootstrapClientId);
            logger.info("Client Secret (plain text): {}", plainSecret);
            logger.info("Grant Types: client_credentials, authorization_code, refresh_token, password");
            logger.info("Scopes: read, write, user:create, user:lock, user:unlock");
            logger.info("=".repeat(80));
            logger.info("You can now use this client to get tokens and access protected endpoints!");
            logger.info("Use the PLAIN TEXT secret '{}' when making requests", plainSecret);
            logger.info("=".repeat(80));
        };
    }
}