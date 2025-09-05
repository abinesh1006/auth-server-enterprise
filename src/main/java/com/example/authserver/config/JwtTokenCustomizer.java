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
                addUserDetails(claims, username, tenantInfo != null ? tenantInfo.toString() : null);
                
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
    
    private void addUserDetails(JwtClaimsSet.Builder claims, String username, String tenant) {
        logger.debug("Adding user details to JWT [username={}]", username);
        
        try {
            UserEntity user = userRepository.findByUsername(username).orElse(null);
            
            if (user != null) {
                claims.claim("user_id", user.getId().toString());
                
                if (user.getEmail() != null) {
                    claims.claim("email", user.getEmail());
                }
                
                if (tenant != null) {
                    claims.claim("user_tenant", tenant);
                }
                
                logger.debug("User details added to JWT [userId={}, email={}]", 
                           user.getId(), user.getEmail() != null ? "present" : "null");
            } else {
                logger.warn("User not found for JWT customization [username={}]", username);
            }
        } catch (Exception e) {
            logger.error("Failed to add user details to JWT [username={}, error={}]", 
                        username, e.getMessage());
        }
    }
}