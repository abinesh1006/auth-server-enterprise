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
        var tenantInfo = TenantContext.get();
        
        // Load user first
        var user = users.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        
        boolean enabled = Boolean.TRUE.equals(user.getIsActive()) && !Boolean.TRUE.equals(user.getIsBlocked());

        if (tenantInfo == null) {
            // No tenant context - return user with no roles
            return new EnhancedUserDetails(
                user.getUsername(),
                user.getPassword(),
                java.util.Set.of(),
                enabled,
                user.getId(),
                user.getEmail()
            );
        }
        
        // Create tenant entity with just the ID since tenant is already cached in TenantResolverFilter
        // This avoids the database query for tenant lookup
        var tenant = createTenantEntity(tenantInfo.id());
        
        // Load roles with optimized query (already uses JOIN FETCH for role data)
        var authorities = userRoles.findByUserAndTenantWithRole(user, tenant)
                .stream()
                .map(ur -> (org.springframework.security.core.GrantedAuthority) new SimpleGrantedAuthority(ur.getRole().getRole()))
                .collect(Collectors.toSet());

        return new EnhancedUserDetails(
            user.getUsername(),
            user.getPassword(),
            authorities,
            enabled,
            user.getId(),
            user.getEmail()
        );
    }
    
    private com.example.authserver.tenant.TenantEntity createTenantEntity(Long tenantId) {
        var tenant = new com.example.authserver.tenant.TenantEntity();
        tenant.setId(tenantId);
        return tenant;
    }
    
    // Enhanced UserDetails class to carry additional user information
    public static class EnhancedUserDetails implements UserDetails {
        private final String username;
        private final String password;
        private final java.util.Set<org.springframework.security.core.GrantedAuthority> authorities;
        private final boolean enabled;
        private final java.util.UUID userId;
        private final String email;
        
        public EnhancedUserDetails(String username, String password, java.util.Set<org.springframework.security.core.GrantedAuthority> authorities, 
                                 boolean enabled, java.util.UUID userId, String email) {
            this.username = username;
            this.password = password;
            this.authorities = authorities;
            this.enabled = enabled;
            this.userId = userId;
            this.email = email;
        }
        
        @Override public String getUsername() { return username; }
        @Override public String getPassword() { return password; }
        @Override public java.util.Collection<? extends org.springframework.security.core.GrantedAuthority> getAuthorities() { return authorities; }
        @Override public boolean isEnabled() { return enabled; }
        @Override public boolean isAccountNonExpired() { return true; }
        @Override public boolean isAccountNonLocked() { return true; }
        @Override public boolean isCredentialsNonExpired() { return true; }
        
        // Additional getters for JWT customization
        public java.util.UUID getUserId() { return userId; }
        public String getEmail() { return email; }
    }
}