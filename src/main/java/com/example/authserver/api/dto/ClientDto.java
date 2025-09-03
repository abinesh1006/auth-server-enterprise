package com.example.authserver.api.dto;

import java.util.Set;

public record ClientDto(
        String clientId,
        String clientSecret,
        Set<String> authenticationMethods,
        Set<String> grantTypes,
        Set<String> redirectUris,
        Set<String> scopes,
        Boolean requirePkce
) {}
