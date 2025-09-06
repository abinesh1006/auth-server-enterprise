package com.example.authserver.tenant;

import com.example.authserver.tenant.TenantRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TenantResolverFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(TenantResolverFilter.class);
    private static final String TENANT_HEADER = "X-Tenant-ID";
    
    private final TenantRepository tenantRepository;
    // Simple in-memory cache to avoid repeated tenant lookups
    private final Map<String, TenantContext.TenantInfo> tenantCache = new ConcurrentHashMap<>();
    private volatile boolean defaultTenantSet = false;
    
    public TenantResolverFilter(TenantRepository tenantRepository) { 
        this.tenantRepository = tenantRepository; 
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        
        // More detailed debugging
        logger.info("TenantResolverFilter: Checking path [{}]", path);
        
        boolean shouldSkip = path.startsWith("/.well-known/") ||           // OIDC Discovery endpoints
               path.startsWith("/oauth2/") ||                 // OAuth2 endpoints (authorize, token, jwks, etc.)
               path.startsWith("/userinfo") ||               // OIDC UserInfo endpoint
               path.startsWith("/actuator/") ||               // Actuator endpoints
               path.startsWith("/swagger-ui/") ||             // Swagger UI
               path.startsWith("/v3/api-docs") ||             // OpenAPI docs
               path.equals("/favicon.ico") ||                 // Favicon
               path.startsWith("/webjars/") ||                // Static resources
               path.startsWith("/css/") ||                    // CSS files
               path.startsWith("/js/") ||                     // JS files
               path.startsWith("/images/");                   // Image files
        
        // Add debugging to see if filter is being skipped
        if (shouldSkip) {
            logger.info("TenantResolverFilter: SKIPPING path [{}]", path);
        } else {
            logger.info("TenantResolverFilter: PROCESSING path [{}]", path);
        }
        
        return shouldSkip;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        
        String correlationId = java.util.UUID.randomUUID().toString().substring(0, 8);
        String tenantId = request.getHeader(TENANT_HEADER);
        String requestUri = request.getRequestURI();
        
        logger.debug("Processing tenant resolution [tenantId={}, uri={}, correlationId={}]", 
                    tenantId, requestUri, correlationId);
        
        try {
            resolveTenant(tenantId, correlationId);
            chain.doFilter(request, response);
        } catch (TenantNotFoundException ex) {
            handleTenantError(response, ex, correlationId);
        } finally {
            logger.debug("Clearing tenant context [correlationId={}]", correlationId);
            TenantContext.clear();
        }
    }
    
    private void handleTenantError(HttpServletResponse response, TenantNotFoundException ex, String correlationId) 
            throws IOException {
        logger.error("Tenant validation failed [correlationId={}]: {}", correlationId, ex.getMessage());
        
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType("application/json");
        
        String errorResponse = String.format(
            "{\"error\":\"invalid_request\",\"error_description\":\"%s\",\"correlation_id\":\"%s\"}",
            ex.getMessage(), correlationId
        );
        
        response.getWriter().write(errorResponse);
        response.getWriter().flush();
    }
    
    private void resolveTenant(String tenantId, String correlationId) {
        // Check if there are any tenants in the database (cache this check)
        if (!defaultTenantSet) {
            long tenantCount = tenantRepository.count();
            if (tenantCount == 0) {
                logger.warn("No tenants found in database, using default tenant [correlationId={}]", correlationId);
                setDefaultTenant();
                return;
            }
            defaultTenantSet = true;
        }
        
        if (tenantId == null || tenantId.trim().isEmpty()) {
            logger.error("Missing {} header in request [correlationId={}]", TENANT_HEADER, correlationId);
            throw new TenantNotFoundException("Missing X-Tenant-ID header");
        }
        
        String trimmedTenantId = tenantId.trim();
        
        // Check cache first to avoid database queries
        TenantContext.TenantInfo cachedTenant = tenantCache.get(trimmedTenantId);
        if (cachedTenant != null) {
            logger.debug("Tenant resolved from cache [tenantId={}, correlationId={}]", trimmedTenantId, correlationId);
            TenantContext.set(cachedTenant);
            return;
        }
        
        // Cache miss - query database
        var tenant = tenantRepository.findByTenantKey(trimmedTenantId).orElse(null);
        
        if (tenant != null) {
            TenantContext.TenantInfo tenantInfo = new TenantContext.TenantInfo(
                tenant.getId(),
                tenant.getTenantKey(), 
                tenant.getDomain()
            );
            
            // Cache the result for future requests
            tenantCache.put(trimmedTenantId, tenantInfo);
            
            logger.debug("Tenant resolved and cached [tenantId={}, domain={}, correlationId={}]", 
                        tenant.getTenantKey(), tenant.getDomain(), correlationId);
            
            TenantContext.set(tenantInfo);
        } else {
            logger.error("Unknown tenant [tenantId={}, correlationId={}]", trimmedTenantId, correlationId);
            logAvailableTenants(correlationId);
            
            // Throw error for unknown tenant
            throw new TenantNotFoundException("Unknown tenant: " + trimmedTenantId);
        }
    }
    
    private void setDefaultTenant() {
        TenantContext.set(new TenantContext.TenantInfo(1L, "default", "localhost"));
        logger.debug("Default tenant context set: {}", TenantContext.get());
    }
    
    private void logAvailableTenants(String correlationId) {
        var allTenants = tenantRepository.findAll();
        if (allTenants.isEmpty()) {
            logger.warn("No tenants exist in database [correlationId={}]", correlationId);
        } else {
            logger.debug("Available tenants [correlationId={}]:", correlationId);
            allTenants.forEach(t -> 
                logger.debug("  - Tenant: {} (domain: {}) [correlationId={}]", 
                            t.getTenantKey(), t.getDomain(), correlationId));
        }
    }
    
    public static class TenantNotFoundException extends RuntimeException {
        public TenantNotFoundException(String message) {
            super(message);
        }
    }
    
    // Optional: Method to clear cache when tenants are updated
    public void clearTenantCache() {
        tenantCache.clear();
        defaultTenantSet = false;
        logger.info("Tenant cache cleared");
    }
}