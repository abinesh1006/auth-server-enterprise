package com.example.authserver.oidc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.authserver.keys.JwkService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class OidcProviderConfigurationController {

    @Value("${server.port:8081}")
    private String serverPort;
    
    @Autowired
    private JwkService jwkService;

    @GetMapping(value = "/.well-known/openid_configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> openidConfiguration() {
        String issuer = "http://localhost:" + serverPort;
        
        Map<String, Object> config = new HashMap<>();
        config.put("issuer", issuer);
        config.put("authorization_endpoint", issuer + "/oauth2/authorize");
        config.put("token_endpoint", issuer + "/oauth2/token");
        config.put("jwks_uri", issuer + "/oauth2/jwks");
        config.put("userinfo_endpoint", issuer + "/userinfo");
        config.put("revocation_endpoint", issuer + "/oauth2/revoke");
        config.put("introspection_endpoint", issuer + "/oauth2/introspect");
        
        // Supported response types
        config.put("response_types_supported", List.of("code", "id_token", "id_token token"));
        
        // Supported grant types
        config.put("grant_types_supported", List.of(
            "authorization_code", 
            "client_credentials", 
            "refresh_token",
            "password"  // Your custom password grant
        ));
        
        // Supported scopes
        config.put("scopes_supported", List.of("openid", "profile", "email", "read", "write"));
        
        // Supported subject types
        config.put("subject_types_supported", List.of("public"));
        
        // Supported signing algorithms
        config.put("id_token_signing_alg_values_supported", List.of("RS256"));
        
        // Supported token endpoint auth methods
        config.put("token_endpoint_auth_methods_supported", List.of(
            "client_secret_basic", 
            "client_secret_post"
        ));
        
        return config;
    }
    
    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Object jwks() {
        // Delegate to the existing JwkService to get the same JWKS data
        // that's served at /oauth2/jwks
        return jwkService;
    }
}