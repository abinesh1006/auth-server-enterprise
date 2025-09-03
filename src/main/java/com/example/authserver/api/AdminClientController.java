package com.example.authserver.api;

import com.example.authserver.api.dto.ClientDto;
import com.example.authserver.client.ClientEntity;
import com.example.authserver.client.ClientService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController @RequestMapping("/api/admin/clients") 
@Tag(name="Admin - Clients")
@SecurityRequirement(name = "bearerAuth")
@SecurityRequirement(name = "oauth2")
public class AdminClientController {
    private final ClientService service;
    public AdminClientController(ClientService service) { this.service = service; }

    @PostMapping
    @PreAuthorize("@rbacService.hasAccess('client:create', authentication)")
    @Operation(summary = "Create OAuth2 client")
    public Map<String,Object> create(@RequestBody ClientDto dto) {
        RegisteredClient rc = service.create(dto.clientId(), dto.clientSecret(), dto.authenticationMethods(), dto.grantTypes(), dto.redirectUris(), dto.scopes(), dto.requirePkce());
        return Map.of("client_id", rc.getClientId(), "id", rc.getId());
    }

    @PutMapping("/{clientId}")
    @PreAuthorize("@rbacService.hasAccess('client:update', authentication)")
    @Operation(summary = "Update OAuth2 client")
    public Map<String,Object> update(@PathVariable String clientId, @RequestBody ClientDto dto) {
        RegisteredClient rc = service.update(clientId, dto.clientSecret(), dto.authenticationMethods(), dto.grantTypes(), dto.redirectUris(), dto.scopes(), dto.requirePkce());
        return Map.of("client_id", rc.getClientId(), "id", rc.getId());
    }

    @GetMapping("/{clientId}")
    @PreAuthorize("@rbacService.hasAccess('client:read', authentication)")
    public Map<String,Object> get(@PathVariable String clientId) {
        RegisteredClient rc = service.get(clientId);
        return Map.of(
                "id", rc.getId(),
                "client_id", rc.getClientId(),
                "grants", rc.getAuthorizationGrantTypes(),
                "scopes", rc.getScopes(),
                "methods", rc.getClientAuthenticationMethods(),
                "redirect_uris", rc.getRedirectUris(),
                "require_pkce", rc.getClientSettings().isRequireProofKey()
        );
    }

    @GetMapping
    @PreAuthorize("@rbacService.hasAccess('client:read', authentication)")
    public List<ClientEntity> list() { return service.list(); }

    @DeleteMapping("/{clientId}")
    @PreAuthorize("@rbacService.hasAccess('client:delete', authentication)")
    public void delete(@PathVariable String clientId) { service.delete(clientId); }
}