package com.example.authserver.tenant;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Map;

@Component
public class TenantExceptionHandler implements HandlerExceptionResolver {
    
    private static final Logger logger = LoggerFactory.getLogger(TenantExceptionHandler.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, 
                                       Object handler, Exception ex) {
        
        if (ex instanceof TenantResolverFilter.TenantNotFoundException) {
            handleTenantNotFoundException(request, response, (TenantResolverFilter.TenantNotFoundException) ex);
            return new ModelAndView(); // Return empty ModelAndView to indicate we handled it
        }
        
        return null; // Let other handlers deal with other exceptions
    }
    
    private void handleTenantNotFoundException(HttpServletRequest request, HttpServletResponse response, 
                                             TenantResolverFilter.TenantNotFoundException ex) {
        try {
            String correlationId = java.util.UUID.randomUUID().toString().substring(0, 8);
            
            logger.error("Tenant not found error [uri={}, correlationId={}]: {}", 
                        request.getRequestURI(), correlationId, ex.getMessage());
            
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            
            Map<String, Object> errorResponse = Map.of(
                "error", "invalid_tenant",
                "error_description", ex.getMessage(),
                "correlation_id", correlationId,
                "timestamp", java.time.Instant.now().toString()
            );
            
            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
            response.getWriter().flush();
            
        } catch (IOException ioEx) {
            logger.error("Failed to write tenant error response", ioEx);
        }
    }
}