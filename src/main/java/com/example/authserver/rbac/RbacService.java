package com.example.authserver.rbac;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service("rbacService")
public class RbacService {
    private final ApiRoleRepository apiRoles;

    public RbacService(ApiRoleRepository apiRoles) { this.apiRoles = apiRoles; }

    public boolean hasAccess(String action, Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) return false;
        Set<String> roles = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        var allowed = apiRoles.findByRole_RoleIn(roles);
        return allowed.stream().anyMatch(ar -> action.equalsIgnoreCase(ar.getAction()));
    }
}
