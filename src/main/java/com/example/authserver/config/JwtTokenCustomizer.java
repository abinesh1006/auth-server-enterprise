package com.example.authserver.config;

import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import com.example.authserver.tenant.TenantContext;
import com.example.authserver.user.UserEntity;
import com.example.authserver.user.UserRepository;

@Component
public class JwtTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenCustomizer.class);
    private final UserRepository userRepository;

    public JwtTokenCustomizer(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
   
    @Override
    public void customize(JwtEncodingContext context) {
        logger.info("=== JWT Token Customizer Starting ===");
        
        try {
            // Log tenant context - safely handle null
            TenantContext.TenantInfo tenantInfo = TenantContext.get();
            String currentTenant = tenantInfo != null ? tenantInfo.toString() : null;
            logger.info("Current tenant context: {}", currentTenant);
            
            JwtClaimsSet.Builder claims = context.getClaims();
            Authentication principal = context.getPrincipal();

            if (principal == null) {
                logger.warn("Principal is null in JWT customizer");
                return;
            }
            
            logger.info("Principal type: {}", principal.getClass().getSimpleName());
            logger.info("Principal name: {}", principal.getName());
            logger.info("Principal authenticated: {}", principal.isAuthenticated());
            logger.info("Principal authorities: {}", principal.getAuthorities());

            // Add authorities/roles to the JWT token
            Set<String> authorities = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

            logger.info("Adding authorities to token: {}", authorities);

            // Add roles as a claim in the JWT
            claims.claim("roles", authorities);
            claims.claim("authorities", authorities);
            
            // Add tenant information if available
            if (currentTenant != null) {
                claims.claim("tenant", currentTenant);
                logger.info("Added tenant to JWT claims: {}", currentTenant);
            } else {
                logger.warn("No tenant context available for JWT token");
            }

            // Add user-specific information if available
            String username = principal.getName();
            if (username != null) {
                claims.claim("preferred_username", username);
                logger.info("Added preferred_username to claims: {}", username);
                
                // Try to add additional user details, but don't fail if it doesn't work
                addUserDetails(claims, username, currentTenant);
                
                // For ID tokens, add additional user info
                if (context.getTokenType() != null && 
                    context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                    claims.claim("name", username);
                    claims.claim("given_name", username);
                    logger.info("Added ID token specific claims for user: {}", username);
                }
            }
            
            logger.info("=== JWT Token Customizer Completed Successfully ===");

        } catch (Exception e) {
            logger.error("=== CRITICAL ERROR in JWT token customizer ===");
            logger.error("Error type: {}", e.getClass().getSimpleName());
            logger.error("Error message: {}", e.getMessage());
            logger.error("Full stack trace:", e);
            logger.error("Tenant context at error: {}", TenantContext.get());
            
            // Don't rethrow the exception - let token generation continue with basic claims
            logger.info("Continuing token generation without custom claims due to error");
        }
    }
    
    private void addUserDetails(JwtClaimsSet.Builder claims, String username, String tenant) {
        logger.info("=== Adding User Details to JWT ===");
        logger.info("Looking up user: {} in tenant: {}", username, tenant);
        
        try {
            UserEntity user = userRepository.findByUsername(username).orElse(null);
            
            if (user != null) {
                logger.info("User found in database: {}", user.getUsername());
                logger.info("User ID: {}", user.getId());
                logger.info("User email: {}", user.getEmail());
                logger.info("User tenant: {}", user.getTenantId());
                
                claims.claim("user_id", user.getId().toString());
                
                if (user.getEmail() != null) {
                    claims.claim("email", user.getEmail());
                }
                
                // Add tenant info from user if available
                if (user.getTenantId() != null) {
                    claims.claim("user_tenant", user.getTenantId());
                    logger.info("Added user tenant to claims: {}", user.getTenantId());
                }
                
                logger.info("Successfully added user details to JWT for user: {}", username);
            } else {
                logger.warn("User NOT found in database: {}", username);
                logger.warn("Database query executed with tenant context: {}", tenant);
            }
        } catch (Exception e) {
            logger.error("=== ERROR loading user details ===");
            logger.error("Username: {}", username);
            logger.error("Tenant context: {}", tenant);
            logger.error("Error type: {}", e.getClass().getSimpleName());
            logger.error("Error message: {}", e.getMessage());
            logger.error("Full error stack:", e);
            
            // Don't rethrow - just log and continue without user details
        }
        
        logger.info("=== User Details Processing Complete ===");
    }
}