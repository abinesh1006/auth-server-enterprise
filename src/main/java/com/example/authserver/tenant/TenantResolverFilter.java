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
    
    private final TenantRepository tenantRepository;
    
    public TenantResolverFilter(TenantRepository tenantRepository) { 
        this.tenantRepository = tenantRepository; 
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        
        logger.info("=== TENANT RESOLVER FILTER STARTING ===");
        logger.info("Request URI: {}", request.getRequestURI());
        logger.info("Request method: {}", request.getMethod());
        
        String host = request.getServerName();
        logger.info("Server name (host): {}", host);
        
        // Check if there are any tenants in the database
        long tenantCount = tenantRepository.count();
        logger.info("Total tenants in database: {}", tenantCount);
        
        if (tenantCount == 0) {
            logger.warn("=== NO TENANTS FOUND IN DATABASE ===");
            logger.warn("Creating default tenant context since no tenants exist");
            
            // Set a default tenant context when no tenants exist
            TenantContext.set(new TenantContext.TenantInfo("default", "default", host, false));
            logger.info("Set default tenant context: {}", TenantContext.get());
        } else {
            logger.info("Looking up tenant by domain: {}", host);
            var tenant = tenantRepository.findByDomain(host).orElse(null);
            
            if (tenant != null) {
                logger.info("=== TENANT FOUND ===");
                logger.info("Tenant ID: {}", tenant.getId());
                logger.info("Tenant Key: {}", tenant.getTenantKey());
                logger.info("Tenant Domain: {}", tenant.getDomain());
                logger.info("MFA Enabled: {}", tenant.getIsMfaEnabled());
                
                TenantContext.set(new TenantContext.TenantInfo(
                    tenant.getId(), 
                    tenant.getTenantKey(), 
                    tenant.getDomain(), 
                    Boolean.TRUE.equals(tenant.getIsMfaEnabled())
                ));
                logger.info("Set tenant context: {}", TenantContext.get());
            } else {
                logger.warn("=== NO TENANT FOUND FOR DOMAIN ===");
                logger.warn("No tenant found for domain: {}", host);
                logger.warn("Available tenants:");
                
                // Log all available tenants for debugging
                var allTenants = tenantRepository.findAll();
                allTenants.forEach(t -> logger.warn("  - Tenant: {} (domain: {})", t.getTenantKey(), t.getDomain()));
                
                if (allTenants.isEmpty()) {
                    logger.warn("No tenants exist in database at all");
                } else {
                    logger.warn("Consider creating a tenant for domain '{}' or using one of the existing domains", host);
                }
                
                // Set a fallback tenant context
                logger.info("Setting fallback default tenant context");
                TenantContext.set(new TenantContext.TenantInfo("default", "default", host, false));
                logger.info("Fallback tenant context set: {}", TenantContext.get());
            }
        }
        
        logger.info("Final tenant context before proceeding: {}", TenantContext.get());
        logger.info("=== TENANT RESOLVER FILTER COMPLETED ===");
        
        try { 
            chain.doFilter(request, response); 
        } finally { 
            logger.debug("Clearing tenant context");
            TenantContext.clear(); 
        }
    }
}