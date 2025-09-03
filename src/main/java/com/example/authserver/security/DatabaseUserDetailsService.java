package com.example.authserver.security;

import com.example.authserver.rbac.UserRoleRepository;
import com.example.authserver.tenant.TenantRepository;
import com.example.authserver.tenant.TenantContext;
import com.example.authserver.user.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
public class DatabaseUserDetailsService implements UserDetailsService {
    private final UserRepository users;
    private final TenantRepository tenants;
    private final UserRoleRepository userRoles;

    public DatabaseUserDetailsService(UserRepository users, TenantRepository tenants, UserRoleRepository userRoles) {
        this.users = users; this.tenants = tenants; this.userRoles = userRoles;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = users.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        boolean enabled = Boolean.TRUE.equals(user.getIsActive()) && !Boolean.TRUE.equals(user.getIsBlocked());

        var tenantInfo = TenantContext.get();
        var tenant = tenantInfo == null ? null : tenants.findById(tenantInfo.id()).orElse(null);

        var authorities = userRoles.findByUserAndTenant(user, tenant).stream()
                .map(ur -> new SimpleGrantedAuthority(ur.getRole().getRole()))
                .collect(Collectors.toSet());

        return org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
                .password(user.getPassword()).authorities(authorities).disabled(!enabled).build();
    }
}
