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

@Component
public class TenantResolverFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(TenantResolverFilter.class);
    private static final String TENANT_HEADER = "X-Tenant-ID";
    
    private final TenantRepository tenantRepository;
    
    public TenantResolverFilter(TenantRepository tenantRepository) { 
        this.tenantRepository = tenantRepository; 
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
        } finally {
            logger.debug("Clearing tenant context [correlationId={}]", correlationId);
            TenantContext.clear();
        }
    }
    
    private void resolveTenant(String tenantId, String correlationId) {
        // Check if there are any tenants in the database
        long tenantCount = tenantRepository.count();
        
        if (tenantCount == 0) {
            logger.warn("No tenants found in database, using default tenant [correlationId={}]", correlationId);
            setDefaultTenant();
            return;
        }
        
        if (tenantId == null || tenantId.trim().isEmpty()) {
            logger.warn("Missing {} header, using default tenant [correlationId={}]", TENANT_HEADER, correlationId);
            setDefaultTenant();
            return;
        }
        
        // Look up tenant by tenant key
        var tenant = tenantRepository.findByTenantKey(tenantId.trim()).orElse(null);
        
        if (tenant != null) {
            logger.debug("Tenant resolved successfully [tenantId={}, domain={}, mfaEnabled={}, correlationId={}]", 
                        tenant.getTenantKey(), tenant.getDomain(), tenant.getIsMfaEnabled(), correlationId);
            
            TenantContext.set(new TenantContext.TenantInfo(
                tenant.getId(),
                tenant.getTenantKey(), 
                tenant.getDomain(), 
                Boolean.TRUE.equals(tenant.getIsMfaEnabled())
            ));
        } else {
            logger.warn("Unknown tenant [tenantId={}, correlationId={}]", tenantId, correlationId);
            logAvailableTenants(correlationId);
            
            // Reject request for unknown tenant
            throw new TenantNotFoundException("Unknown tenant: " + tenantId);
        }
    }
    
    private void setDefaultTenant() {
        TenantContext.set(new TenantContext.TenantInfo(1L, "default", "localhost", false));
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
}