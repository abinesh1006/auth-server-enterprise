package com.example.authserver.client;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ClientService {
    private final DbRegisteredClientRepository repo;

    public ClientService(DbRegisteredClientRepository repo) { this.repo = repo; }

    @Transactional
    public RegisteredClient create(String clientId, String secret, Set<String> authMethods, Set<String> grants,
                                   Set<String> redirectUris, Set<String> scopes, Boolean requirePkce) {
        RegisteredClient.Builder b = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(secret)
                .clientSettings(ClientSettings.builder().requireProofKey(Boolean.TRUE.equals(requirePkce)).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .build());
        if (authMethods!=null) authMethods.forEach(m -> b.clientAuthenticationMethod(new ClientAuthenticationMethod(m)));
        if (grants!=null) grants.forEach(g -> b.authorizationGrantType(new AuthorizationGrantType(g)));
        if (redirectUris!=null) redirectUris.forEach(b::redirectUri);
        if (scopes!=null) scopes.forEach(b::scope);
        RegisteredClient rc = b.build();
        repo.save(rc);
        return rc;
    }

    @Transactional
    public RegisteredClient update(String clientId, String secret, Set<String> authMethods, Set<String> grants,
                                   Set<String> redirectUris, Set<String> scopes, Boolean requirePkce) {
        RegisteredClient existing = repo.findByClientId(clientId);
        if (existing == null) throw new IllegalArgumentException("Client not found");
        RegisteredClient.Builder b = RegisteredClient.withId(existing.getId())
                .clientId(existing.getClientId())
                .clientSecret(secret != null ? secret : existing.getClientSecret())
                .clientSettings(ClientSettings.builder()
                        .settings(settings -> settings.putAll(existing.getClientSettings().getSettings()))
                        .requireProofKey(requirePkce != null ? requirePkce : existing.getClientSettings().isRequireProofKey())
                        .build())
                .tokenSettings(existing.getTokenSettings());
        Set<String> am = authMethods != null ? authMethods : existing.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue).collect(java.util.stream.Collectors.toSet());
        Set<String> gt = grants != null ? grants : existing.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).collect(java.util.stream.Collectors.toSet());
        Set<String> ru = redirectUris != null ? redirectUris : existing.getRedirectUris();
        Set<String> sc = scopes != null ? scopes : existing.getScopes();
        am.forEach(m -> b.clientAuthenticationMethod(new ClientAuthenticationMethod(m)));
        gt.forEach(g -> b.authorizationGrantType(new AuthorizationGrantType(g)));
        ru.forEach(b::redirectUri);
        sc.forEach(b::scope);
        RegisteredClient rc = b.build();
        repo.save(rc);
        return rc;
    }

    public RegisteredClient get(String clientId) { return repo.findByClientId(clientId); }

    public List<ClientEntity> list() { return repo.repository.findAll(); }

    @Transactional
    public void delete(String clientId) {
        var entity = repo.repository.findByClientId(clientId).orElseThrow();
        repo.repository.delete(entity);
    }
}