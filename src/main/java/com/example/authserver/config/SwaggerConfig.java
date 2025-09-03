package com.example.authserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

@Configuration
public class SwaggerConfig {

    @Value("${spring.security.oauth2.authorizationserver.issuer}")
    private String issuer;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("Auth Server Enterprise API")
                .version("v1")
                .description("Spring Authorization Server Enterprise: Multi-tenant, MFA, JWT Client Registration"))
            .components(new Components()
                .addSecuritySchemes("bearerAuth",
                    new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("JWT Bearer token"))
                .addSecuritySchemes("oauth2",
                    new SecurityScheme()
                        .type(SecurityScheme.Type.OAUTH2)
                        .description("OAuth2 flow")
                        .flows(new OAuthFlows()
                            .authorizationCode(new OAuthFlow()
                                .authorizationUrl(issuer + "/oauth2/authorize")
                                .tokenUrl(issuer + "/oauth2/token")
                                .refreshUrl(issuer + "/oauth2/token")
                                .scopes(new Scopes()
                                    .addString("openid", "OpenID Connect")
                                    .addString("profile", "User profile information")
                                    .addString("read", "Read access")
                                    .addString("write", "Write access")
                                    .addString("user:create", "Create users")
                                    .addString("user:lock", "Lock users")
                                    .addString("user:unlock", "Unlock users")))
                            .clientCredentials(new OAuthFlow()
                                .tokenUrl(issuer + "/oauth2/token")
                                .scopes(new Scopes()
                                    .addString("read", "Read access")
                                    .addString("write", "Write access")
                                    .addString("user:create", "Create users")
                                    .addString("user:lock", "Lock users")
                                    .addString("user:unlock", "Unlock users"))))))
            .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
            .addSecurityItem(new SecurityRequirement().addList("oauth2"));
    }
}