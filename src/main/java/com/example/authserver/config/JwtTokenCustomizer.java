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

import com.example.authserver.security.DatabaseUserDetailsService;
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
        String correlationId = java.util.UUID.randomUUID().toString().substring(0, 8);
        logger.debug("Customizing JWT token [correlationId={}]", correlationId);
        
        try {
            TenantContext.TenantInfo tenantInfo = TenantContext.get();
            JwtClaimsSet.Builder claims = context.getClaims();
            Authentication principal = context.getPrincipal();

            if (principal == null) {
                logger.warn("Principal is null in JWT customizer [correlationId={}]", correlationId);
                return;
            }
            
            String username = principal.getName();
            logger.debug("Customizing JWT for user [username={}, correlationId={}]", username, correlationId);

            // Add authorities/roles to the JWT token
            Set<String> authorities = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

            claims.claim("roles", authorities);
            claims.claim("authorities", authorities);
            
            // Add tenant information if available
            if (tenantInfo != null) {
                claims.claim("tenant", tenantInfo.key());
                logger.debug("Added tenant to JWT [tenant={}, correlationId={}]", tenantInfo.key(), correlationId);
            }

            // Add user-specific information
            if (username != null) {
                claims.claim("preferred_username", username);
                
                // Try to get user details from UserDetails if available to avoid additional DB query
                if (principal instanceof org.springframework.security.authentication.UsernamePasswordAuthenticationToken) {
                    var authToken = (org.springframework.security.authentication.UsernamePasswordAuthenticationToken) principal;
                    if (authToken.getDetails() instanceof org.springframework.security.core.userdetails.UserDetails) {
                        // UserDetails is available, try to extract additional info if needed
                        addUserDetailsFromPrincipal(claims, authToken, tenantInfo, correlationId);
                    } else {
                        // Fallback to database lookup (this should be rare)
                        addUserDetailsFromDatabase(claims, username, tenantInfo, correlationId);
                    }
                } else {
                    // Fallback to database lookup
                    addUserDetailsFromDatabase(claims, username, tenantInfo, correlationId);
                }
                
                // For ID tokens, add additional user info
                if (context.getTokenType() != null && 
                    context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                    claims.claim("name", username);
                    claims.claim("given_name", username);
                }
            }
            
            logger.debug("JWT token customization completed [correlationId={}]", correlationId);

        } catch (Exception e) {
            logger.error("JWT token customization failed [correlationId={}, error={}]", 
                        correlationId, e.getMessage(), e);
        }
    }
    
    private void addUserDetailsFromPrincipal(JwtClaimsSet.Builder claims, 
                                           org.springframework.security.authentication.UsernamePasswordAuthenticationToken authToken,
                                           TenantContext.TenantInfo tenantInfo, 
                                           String correlationId) {
        logger.debug("Using cached user details from authentication token [correlationId={}]", correlationId);
        
        // Try to get enhanced user details from the authentication token
        Object principal = authToken.getPrincipal();
        if (principal instanceof DatabaseUserDetailsService.EnhancedUserDetails) {
            DatabaseUserDetailsService.EnhancedUserDetails enhancedUser = 
                (DatabaseUserDetailsService.EnhancedUserDetails) principal;
            
            // Add user details from cached UserDetails (no database query needed!)
            claims.claim("user_id", enhancedUser.getUserId().toString());
            claims.claim("preferred_username", enhancedUser.getUsername());
            
            if (enhancedUser.getEmail() != null) {
                claims.claim("email", enhancedUser.getEmail());
            }
            
            if (tenantInfo != null) {
                claims.claim("user_tenant", tenantInfo.key());
            }
            
            logger.debug("User details added from cached UserDetails [userId={}, email={}, correlationId={}]", 
                        enhancedUser.getUserId(), 
                        enhancedUser.getEmail() != null ? "present" : "null", 
                        correlationId);
        } else {
            // Fallback to database lookup if enhanced UserDetails not available
            logger.debug("Enhanced UserDetails not available, falling back to database lookup [correlationId={}]", correlationId);
            addUserDetailsFromDatabase(claims, authToken.getName(), tenantInfo, correlationId);
        }
    }
    
    private void addUserDetailsFromDatabase(JwtClaimsSet.Builder claims, String username, 
                                          TenantContext.TenantInfo tenantInfo, String correlationId) {
        logger.debug("Loading user details from database [username={}, correlationId={}]", username, correlationId);
        
        try {
            UserEntity user = userRepository.findByUsername(username).orElse(null);
            
            if (user != null) {
                claims.claim("user_id", user.getId().toString());
                
                if (user.getEmail() != null) {
                    claims.claim("email", user.getEmail());
                }
                
                if (tenantInfo != null) {
                    claims.claim("user_tenant", tenantInfo.key());
                }
                
                logger.debug("User details added to JWT [userId={}, email={}, correlationId={}]", 
                           user.getId(), user.getEmail() != null ? "present" : "null", correlationId);
            } else {
                logger.warn("User not found for JWT customization [username={}, correlationId={}]", username, correlationId);
            }
        } catch (Exception e) {
            logger.error("Failed to add user details to JWT [username={}, correlationId={}, error={}]", 
                        username, correlationId, e.getMessage());
        }
    }
}