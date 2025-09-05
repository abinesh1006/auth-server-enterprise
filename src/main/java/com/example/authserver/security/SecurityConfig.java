package com.example.authserver.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.authserver.client.DbRegisteredClientRepository;
import com.example.authserver.keys.JwkService;
import com.example.authserver.mfa.MfaService;
import com.example.authserver.password.PasswordAuthenticationConverter;
import com.example.authserver.password.PasswordAuthenticationProvider;
import com.example.authserver.tenant.TenantResolverFilter;

@Configuration
public class SecurityConfig {

    private final TenantResolverFilter tenantFilter;
    private final DbRegisteredClientRepository clientRepository;
    private final JwkService jwkSource;

    public SecurityConfig(TenantResolverFilter tenantFilter, DbRegisteredClientRepository clientRepository, JwkService jwkSource) {
        this.tenantFilter = tenantFilter; this.clientRepository = clientRepository; this.jwkSource = jwkSource;
    }

    @Bean public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService uds, PasswordEncoder encoder) {
        var dao = new DaoAuthenticationProvider(); dao.setUserDetailsService(uds); dao.setPasswordEncoder(encoder);
        return new ProviderManager(dao);
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerChain(HttpSecurity http,
                                               AuthenticationManager authenticationManager,
                                               org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizationService,
                                               OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                               MfaService mfaService) throws Exception {

        // Apply OAuth2 Authorization Server default security first
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        
        // Configure OAuth2 Authorization Server specific settings
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(oidc -> oidc
                .providerConfigurationEndpoint(Customizer.withDefaults())
                .userInfoEndpoint(Customizer.withDefaults())
            )
            .clientAuthentication(clientAuth -> clientAuth
                .authenticationConverter(new org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretPostAuthenticationConverter())
                .authenticationConverter(new org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter())
            )
            .tokenEndpoint(token -> token
                .accessTokenRequestConverter(new PasswordAuthenticationConverter())
                .authenticationProvider(new PasswordAuthenticationProvider(authenticationManager, authorizationService, tokenGenerator, mfaService))
            );

        // Configure OAuth2 resource server and other settings
        http.oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()))
            .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain appChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(a -> a
                .requestMatchers("/", "/actuator/health").permitAll()
                .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**", "/swagger-resources/**", "/webjars/**").permitAll()
                .requestMatchers("/api/public/**", "/api/clients/register", "/api/clients/register/simple").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()))
            .addFilterBefore(tenantFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizationService() {
        return new org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService authorizationConsentService() {
        return new org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService();
    }

    @Bean public JwtDecoder jwtDecoder(JwkService jwkSource) { return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource); }
    @Bean public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JwkService jwkSource, org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer<org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext> jwtCustomizer) {
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        
        // Configure access token generator to use JWT format
        accessTokenGenerator.setAccessTokenCustomizer(context -> {
            // The access token generator will create OAuth2AccessToken objects
            // The JWT customizer will be applied when needed for JWT encoding
        });
        
        return new DelegatingOAuth2TokenGenerator(accessTokenGenerator, refreshTokenGenerator, jwtGenerator);
    }
}