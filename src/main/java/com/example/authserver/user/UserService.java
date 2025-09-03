package com.example.authserver.user;

import com.example.authserver.rbac.RoleEntity;
import com.example.authserver.rbac.RoleRepository;
import com.example.authserver.rbac.UserRoleEntity;
import com.example.authserver.rbac.UserRoleRepository;
import com.example.authserver.tenant.TenantRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class UserService {
    private final UserRepository users;
    private final RoleRepository roles;
    private final UserRoleRepository userRoles;
    private final TenantRepository tenants;
    private final PasswordEncoder encoder;

    public UserService(UserRepository users, RoleRepository roles, UserRoleRepository userRoles, TenantRepository tenants, PasswordEncoder encoder) {
        this.users = users; this.roles = roles; this.userRoles = userRoles; this.tenants = tenants; this.encoder = encoder;
    }

    @Transactional
    public UserEntity createUser(String username, String email, String rawPassword, String tenantKey, Set<String> roleNames) {
        UserEntity u = new UserEntity();
        u.setUsername(username);
        u.setEmail(email);
        u.setPassword(encoder.encode(rawPassword));
        users.save(u);

        var tenant = tenants.findByTenantKey(tenantKey).orElseThrow();

        for (String r : roleNames) {
            RoleEntity role = roles.findByRole(r).orElseGet(() -> {
                RoleEntity nr = new RoleEntity();
                nr.setRole(r);
                return roles.save(nr);
            });
            UserRoleEntity map = new UserRoleEntity();
            map.setTenant(tenant); map.setUser(u); map.setRole(role);
            userRoles.save(map);
        }
        return u;
    }

    public void lockUser(String username) {
        var u = users.findByUsername(username).orElseThrow();
        u.setIsBlocked(true);
        users.save(u);
    }

    public void unlockUser(String username) {
        var u = users.findByUsername(username).orElseThrow();
        u.setIsBlocked(false);
        users.save(u);
    }
}
