package com.example.authserver.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
public class ClientRegistrationService {

    private final DbRegisteredClientRepository repo;
    private final ObjectMapper mapper;

    @Value("${app.client-registration.hmac-secret}")
    private String hmacSecret;

    public ClientRegistrationService(DbRegisteredClientRepository repo, ObjectMapper mapper) {
        this.repo = repo; this.mapper = mapper;
    }

    public RegisteredClient registerFromJwt(String jwsCompact) {
        Map<String,Object> claims = verifyHmacJws(jwsCompact);
        String clientId = (String) claims.getOrDefault("client_id", UUID.randomUUID().toString());
        String clientSecret = (String) claims.getOrDefault("client_secret", null);
        Set<String> scopes = Set.copyOf((java.util.List<String>) claims.getOrDefault("scopes", java.util.List.of("openid","profile")));
        Set<String> grants = Set.copyOf((java.util.List<String>) claims.getOrDefault("grant_types", java.util.List.of("authorization_code","refresh_token")));
        Set<String> redirects = Set.copyOf((java.util.List<String>) claims.getOrDefault("redirect_uris", java.util.List.of()));
        Set<String> methods = Set.copyOf((java.util.List<String>) claims.getOrDefault("auth_methods", java.util.List.of("client_secret_basic")));
        boolean requirePkce = (boolean) claims.getOrDefault("require_pkce", Boolean.FALSE);

        ClientSettings clientSettings = ClientSettings.builder().requireProofKey(requirePkce).build();
        TokenSettings tokenSettings = TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(15)).refreshTokenTimeToLive(Duration.ofDays(30)).build();

        RegisteredClient.Builder b = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId).clientSecret(clientSecret)
                .clientSettings(clientSettings).tokenSettings(tokenSettings);

        methods.forEach(m -> b.clientAuthenticationMethod(new ClientAuthenticationMethod(m)));
        grants.forEach(g -> b.authorizationGrantType(new AuthorizationGrantType(g)));
        redirects.forEach(b::redirectUri);
        scopes.forEach(b::scope);

        RegisteredClient rc = b.build();
        repo.save(rc);
        return rc;
    }

    public RegisteredClient registerSimpleClient(String clientId, String clientSecret, String redirectUri) {
        // Create a simple client with common defaults for development
        ClientSettings clientSettings = ClientSettings.builder()
                .requireProofKey(false) // Disable PKCE for simplicity
                .requireAuthorizationConsent(false) // Skip consent for development
                .build();
        
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(1))
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .reuseRefreshTokens(true)
                .build();

        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret("{noop}" + clientSecret) // Plain text secret for development
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirectUri)
                .scope("read")
                .scope("write")
                .scope("user:create")
                .scope("user:lock")
                .scope("user:unlock")
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();

        repo.save(client);
        return client;
    }

    private Map<String,Object> verifyHmacJws(String compact) {
        try {
            String[] parts = compact.split("\\.");
            if (parts.length != 3) throw new IllegalArgumentException("Invalid JWS");
            byte[] header = Base64.getUrlDecoder().decode(parts[0]);
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            byte[] sig = Base64.getUrlDecoder().decode(parts[2]);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] expected = mac.doFinal((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!java.util.Arrays.equals(sig, expected)) throw new IllegalArgumentException("Bad signature");
            return mapper.readValue(payload, Map.class);
        } catch (Exception e) { throw new IllegalArgumentException("Invalid registration JWT: " + e.getMessage(), e); }
    }
}