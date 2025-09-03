package com.example.authserver.api.dto;
public record TenantDto(String tenantKey, String domain, Boolean mfaEnabled, String owner) {}
