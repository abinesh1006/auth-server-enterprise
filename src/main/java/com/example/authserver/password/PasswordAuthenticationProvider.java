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
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import com.example.authserver.mfa.MfaService;
import com.example.authserver.tenant.TenantContext;

public class PasswordAuthenticationProvider implements org.springframework.security.authentication.AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(PasswordAuthenticationProvider.class);
    
    private final AuthenticationManager authenticationManager;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final MfaService mfaService;

    public PasswordAuthenticationProvider(AuthenticationManager authenticationManager,
                                          OAuth2AuthorizationService authorizationService,
                                          OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                          MfaService mfaService) {
        this.authenticationManager = authenticationManager;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.mfaService = mfaService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        logger.info("=== PASSWORD AUTHENTICATION PROVIDER STARTING ===");
        
        try {
            PasswordAuthenticationToken request = (PasswordAuthenticationToken) authentication;
            OAuth2ClientAuthenticationToken clientAuth = (OAuth2ClientAuthenticationToken) request.getPrincipal();
            RegisteredClient client = clientAuth.getRegisteredClient();
            
            logger.info("Client ID: {}", client != null ? client.getClientId() : "NULL");
            logger.info("Username: {}", request.getUsername());
            logger.info("Tenant context at start: {}", TenantContext.get());
            
            if (client == null || client.getAuthorizationGrantTypes().stream().noneMatch(gt -> gt.getValue().equals(PasswordGrantType.GRANT_TYPE))) {
                logger.error("Client does not support password grant type");
                logger.error("Client: {}", client);
                logger.error("Supported grant types: {}", client != null ? client.getAuthorizationGrantTypes() : "NULL");
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
            }

            logger.info("=== CALLING AUTHENTICATION MANAGER ===");
            logger.info("About to authenticate user: {} with AuthenticationManager", request.getUsername());
            logger.info("Tenant context before user auth: {}", TenantContext.get());
            
            Authentication userAuth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
            
            logger.info("=== USER AUTHENTICATION COMPLETED ===");
            logger.info("User authenticated successfully: {}", userAuth.isAuthenticated());
            logger.info("User principal: {}", userAuth.getPrincipal());
            logger.info("User authorities: {}", userAuth.getAuthorities());
            logger.info("Tenant context after user auth: {}", TenantContext.get());

            var tenant = TenantContext.get();
            boolean mfaRequired = tenant != null && tenant.equals("tenant-with-mfa-enabled"); // Adjust this logic
            logger.info("MFA required: {}, Tenant: {}", mfaRequired, tenant);
            
            if (mfaRequired) {
                if (request.getMfaCode() == null || !mfaService.verify(request.getUsername(), request.getMfaCode())) {
                    logger.error("MFA verification failed for user: {}", request.getUsername());
                    throw new OAuth2AuthenticationException(new OAuth2Error("mfa_required", "MFA required or invalid", null));
                }
                logger.info("MFA verification successful for user: {}", request.getUsername());
            }

            Set<String> authorizedScopes = request.getScopes().isEmpty() ? client.getScopes()
                    : request.getScopes().stream().filter(client.getScopes()::contains).collect(Collectors.toSet());

            logger.info("Authorized scopes: {}", authorizedScopes);
            logger.info("Tenant context before token generation: {}", TenantContext.get());

            DefaultOAuth2TokenContext.Builder tokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(client).principal(userAuth)
                    .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                    .authorizedScopes(authorizedScopes)
                    .authorizationGrantType(new AuthorizationGrantType(PasswordGrantType.GRANT_TYPE))
                    .authorizationGrant(request);

            logger.info("=== GENERATING ACCESS TOKEN ===");
            DefaultOAuth2TokenContext accessTokenContext = tokenContext.build();
            OAuth2AccessToken access = (OAuth2AccessToken) tokenGenerator.generate(accessTokenContext);
            
            if (access == null) {
                logger.error("=== ACCESS TOKEN IS NULL ===");
                logger.error("TokenGenerator returned null for access token");
                logger.error("Token context: {}", accessTokenContext);
                logger.error("Tenant context: {}", TenantContext.get());
                throw new OAuth2AuthenticationException(new OAuth2Error("server_error", "Failed to generate access token", null));
            }
            
            logger.info("Access token generated successfully: {}", access.getTokenValue().substring(0, 20) + "...");

            logger.info("=== GENERATING REFRESH TOKEN ===");
            DefaultOAuth2TokenContext refreshTokenContext = tokenContext.build();
            OAuth2RefreshToken refresh = (OAuth2RefreshToken) tokenGenerator.generate(refreshTokenContext);
            
            if (refresh == null) {
                logger.warn("Refresh token is null - this might be expected based on client configuration");
            } else {
                logger.info("Refresh token generated successfully");
            }

            logger.info("=== SAVING AUTHORIZATION ===");
            logger.info("Tenant context before saving authorization: {}", TenantContext.get());
            
            OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                    .principalName(userAuth.getName())
                    .authorizationGrantType(new AuthorizationGrantType(PasswordGrantType.GRANT_TYPE))
                    .authorizedScopes(authorizedScopes)
                    .token(access);
            
            if (refresh != null) {
                authorization = authorization.refreshToken(refresh);
            }
            
            authorization = authorization.build();
            authorizationService.save(authorization);
            
            logger.info("Authorization saved successfully");
            logger.info("=== PASSWORD AUTHENTICATION PROVIDER COMPLETED SUCCESSFULLY ===");

            return new OAuth2AccessTokenAuthenticationToken(client, clientAuth, access, refresh, Map.of());
            
        } catch (Exception e) {
            logger.error("=== CRITICAL ERROR IN PASSWORD AUTHENTICATION PROVIDER ===");
            logger.error("Error type: {}", e.getClass().getSimpleName());
            logger.error("Error message: {}", e.getMessage());
            logger.error("Tenant context at error: {}", TenantContext.get());
            logger.error("Full stack trace:", e);
            
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