package com.example.authserver.api.dto;
import java.util.Set;
public record UserDto(String username, String email, String password, Set<String> roles, String tenantKey) { }
