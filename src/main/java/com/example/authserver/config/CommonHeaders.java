package com.example.authserver.config;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Schema;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Parameter(
    name = "X-Tenant-ID",
    description = "Tenant identifier for multi-tenant operations",
    required = false,
    in = ParameterIn.HEADER,
    schema = @Schema(type = "string")
)
@Parameter(
    name = "X-Correlation-ID", 
    description = "Correlation ID for request tracing",
    required = false,
    in = ParameterIn.HEADER,
    schema = @Schema(type = "string")
)
@Parameter(
    name = "X-Request-ID",
    description = "Unique request identifier", 
    required = false,
    in = ParameterIn.HEADER,
    schema = @Schema(type = "string")
)
public @interface CommonHeaders {
}