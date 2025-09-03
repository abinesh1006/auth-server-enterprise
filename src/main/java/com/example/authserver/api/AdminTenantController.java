package com.example.authserver.api;

import com.example.authserver.api.dto.TenantDto;
import com.example.authserver.tenant.TenantEntity;
import com.example.authserver.tenant.TenantService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController @RequestMapping("/api/admin/tenants") 
@Tag(name="Admin - Tenants")
@SecurityRequirement(name = "bearerAuth")
@SecurityRequirement(name = "oauth2")
public class AdminTenantController {
    private final TenantService service;
    public AdminTenantController(TenantService service) { this.service = service; }

    @PostMapping
    @Operation(summary = "Create tenant")
    public TenantEntity create(@RequestBody TenantDto dto) {
        return service.create(dto.tenantKey(), dto.domain(), dto.mfaEnabled(), dto.owner());
    }

    @PutMapping("/{id}")
    @PreAuthorize("@rbacService.hasAccess('tenant:update', authentication)")
    @Operation(summary = "Update tenant")
    public TenantEntity update(@PathVariable Long id, @RequestBody TenantDto dto) {
        return service.update(id, dto.tenantKey(), dto.domain(), dto.mfaEnabled(), dto.owner());
    }

    @GetMapping("/{id}")
    @PreAuthorize("@rbacService.hasAccess('tenant:read', authentication)")
    public TenantEntity get(@PathVariable Long id) { return service.get(id); }

    @GetMapping
    @PreAuthorize("@rbacService.hasAccess('tenant:read', authentication)")
    public List<TenantEntity> list() { return service.list(); }

    @DeleteMapping("/{id}")
    @PreAuthorize("@rbacService.hasAccess('tenant:delete', authentication)")
    public void delete(@PathVariable Long id) { service.delete(id); }
}