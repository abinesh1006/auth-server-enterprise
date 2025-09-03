package com.example.authserver.api;

import com.example.authserver.client.ClientRegistrationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController @RequestMapping("/api/clients") @Tag(name="Clients")
public class ClientController {
    private final ClientRegistrationService service;
    public ClientController(ClientRegistrationService service) { this.service = service; }

    @PostMapping("/register")
    @Operation(summary = "Dynamic client registration using a signed JWT (HMAC HS256) with client metadata")
    public Map<String,Object> register(@RequestBody Map<String,String> body) {
        var rc = service.registerFromJwt(body.get("registration_jwt"));
        return Map.of("client_id", rc.getClientId(), "grants", rc.getAuthorizationGrantTypes(), "scopes", rc.getScopes());
    }

    @PostMapping("/register/simple")
    @Operation(summary = "Simple client registration for development (no JWT required)")
    public Map<String, Object> registerSimple(@RequestBody Map<String, Object> clientRequest) {
        String clientId = (String) clientRequest.getOrDefault("client_id", "client-" + System.currentTimeMillis());
        String clientSecret = (String) clientRequest.getOrDefault("client_secret", "secret-" + System.currentTimeMillis());
        String redirectUri = (String) clientRequest.getOrDefault("redirect_uri", "https://oauth.pstmn.io/v1/callback");

        var rc = service.registerSimpleClient(clientId, clientSecret, redirectUri);

        return Map.of(
            "client_id", rc.getClientId(),
            "client_secret", clientSecret,
            "grants", rc.getAuthorizationGrantTypes(),
            "scopes", rc.getScopes(),
            "redirect_uris", rc.getRedirectUris()
        );
    }
}