package com.example.authserver.password;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import com.example.authserver.tenant.TenantContext;

public class PasswordAuthenticationProvider implements org.springframework.security.authentication.AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(PasswordAuthenticationProvider.class);
    
    private final AuthenticationManager authenticationManager;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    public PasswordAuthenticationProvider(AuthenticationManager authenticationManager,
                                          OAuth2AuthorizationService authorizationService,
                                          OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        this.authenticationManager = authenticationManager;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        String correlationId = java.util.UUID.randomUUID().toString().substring(0, 8);
        logger.debug("Starting password authentication process [correlationId={}]", correlationId);
        
        try {
            PasswordAuthenticationToken request = (PasswordAuthenticationToken) authentication;
            OAuth2ClientAuthenticationToken clientAuth = (OAuth2ClientAuthenticationToken) request.getPrincipal();
            RegisteredClient client = clientAuth.getRegisteredClient();
            
            String clientId = client != null ? client.getClientId() : "unknown";
            String username = request.getUsername();
            TenantContext.TenantInfo tenantInfo = TenantContext.get();
            String tenant = tenantInfo != null ? tenantInfo.key() : null;
            
            logger.info("Authenticating user [username={}, clientId={}, tenant={}, correlationId={}]", 
                       username, clientId, tenant, correlationId);
            
            if (client == null || client.getAuthorizationGrantTypes().stream().noneMatch(gt -> gt.getValue().equals(PasswordGrantType.GRANT_TYPE))) {
                logger.warn("Client does not support password grant type [clientId={}, grantTypes={}, correlationId={}]", 
                           clientId, client != null ? client.getAuthorizationGrantTypes() : "null", correlationId);
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
            }

            logger.debug("Delegating to authentication manager [username={}, correlationId={}]", username, correlationId);
            
            Authentication userAuth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
            
            logger.debug("User authentication completed [username={}, authenticated={}, authorities={}, correlationId={}]", 
                        username, userAuth.isAuthenticated(), userAuth.getAuthorities().size(), correlationId);

            Set<String> authorizedScopes = request.getScopes().isEmpty() ? client.getScopes()
                    : request.getScopes().stream().filter(client.getScopes()::contains).collect(Collectors.toSet());

            logger.debug("Scope authorization completed [authorizedScopes={}, correlationId={}]", authorizedScopes, correlationId);

            DefaultOAuth2TokenContext.Builder tokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(client).principal(userAuth)
                    .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                    .authorizedScopes(authorizedScopes)
                    .authorizationGrantType(new AuthorizationGrantType(PasswordGrantType.GRANT_TYPE))
                    .authorizationGrant(request);

            logger.debug("Generating access token [correlationId={}]", correlationId);
            DefaultOAuth2TokenContext accessTokenContext = tokenContext
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                    .build();
            OAuth2Token generatedToken = tokenGenerator.generate(accessTokenContext);
            
            if (generatedToken == null) {
                logger.error("Access token generation failed - token generator returned null [correlationId={}]", correlationId);
                throw new OAuth2AuthenticationException(new OAuth2Error("server_error", "Failed to generate access token", null));
            }
            
            OAuth2AccessToken access;
            if (generatedToken instanceof OAuth2AccessToken) {
                access = (OAuth2AccessToken) generatedToken;
            } else if (generatedToken instanceof org.springframework.security.oauth2.jwt.Jwt) {
                // Handle JWT case - convert to OAuth2AccessToken
                org.springframework.security.oauth2.jwt.Jwt jwt = (org.springframework.security.oauth2.jwt.Jwt) generatedToken;
                access = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    jwt.getTokenValue(),
                    jwt.getIssuedAt(),
                    jwt.getExpiresAt(),
                    authorizedScopes
                );
                logger.debug("Converted JWT to OAuth2AccessToken [correlationId={}]", correlationId);
            } else {
                logger.error("Unexpected token type generated [tokenType={}, correlationId={}]", 
                           generatedToken.getClass().getSimpleName(), correlationId);
                throw new OAuth2AuthenticationException(new OAuth2Error("server_error", "Unexpected token type generated", null));
            }
            
            logger.debug("Access token generated successfully [correlationId={}]", correlationId);

            logger.debug("Generating refresh token [correlationId={}]", correlationId);
            DefaultOAuth2TokenContext refreshTokenContext = tokenContext
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();
            OAuth2RefreshToken refresh = (OAuth2RefreshToken) tokenGenerator.generate(refreshTokenContext);
            
            if (refresh == null) {
                logger.debug("Refresh token not generated - may be disabled for client [clientId={}, correlationId={}]", clientId, correlationId);
            } else {
                logger.debug("Refresh token generated successfully [correlationId={}]", correlationId);
            }

            logger.debug("Persisting OAuth2 authorization [correlationId={}]", correlationId);
            
            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(client)
                    .principalName(userAuth.getName())
                    .authorizationGrantType(new AuthorizationGrantType(PasswordGrantType.GRANT_TYPE))
                    .authorizedScopes(authorizedScopes)
                    .token(access);
            
            if (refresh != null) {
                authorizationBuilder = authorizationBuilder.refreshToken(refresh);
            }
            
            OAuth2Authorization authorization = authorizationBuilder.build();
            authorizationService.save(authorization);
            
            logger.info("Password authentication completed successfully [username={}, clientId={}, scopes={}, correlationId={}]", 
                       username, clientId, authorizedScopes, correlationId);

            return new OAuth2AccessTokenAuthenticationToken(client, clientAuth, access, refresh, Map.of());
            
        } catch (Exception e) {
            logger.error("Password authentication failed [correlationId={}, errorType={}, message={}]", 
                        correlationId, e.getClass().getSimpleName(), e.getMessage(), e);
            
            if (e instanceof OAuth2AuthenticationException) {
                throw e; // Re-throw OAuth2 exceptions as-is
            } else {
                throw new OAuth2AuthenticationException(new OAuth2Error("server_error", "Authentication failed: " + e.getMessage(), null));
            }
        }
    }

    @Override 
    public boolean supports(Class<?> authentication) { 
        boolean supports = PasswordAuthenticationToken.class.isAssignableFrom(authentication);
        logger.debug("PasswordAuthenticationProvider supports {}: {}", authentication.getSimpleName(), supports);
        return supports;
    }
}