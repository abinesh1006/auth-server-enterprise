package com.example.authserver.api;

import com.example.authserver.api.dto.UserDto;
import com.example.authserver.user.UserEntity;
import com.example.authserver.user.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController @RequestMapping("/api/users")
@Tag(name="Users")
@SecurityRequirement(name = "bearerAuth")
@SecurityRequirement(name = "oauth2")
public class UserController {
    private final UserService userService;
    public UserController(UserService userService) { this.userService = userService; }

    @PostMapping
    @Operation(summary = "Create user and assign roles for a tenant")
    public UserEntity create(@RequestBody UserDto dto) {
        return userService.createUser(dto.username(), dto.email(), dto.password(), dto.tenantKey(), dto.roles());
    }

    
    @PostMapping("/{username}/lock")
    @PreAuthorize("@rbacService.hasAccess('user:lock', authentication)")
    @Operation(summary = "Lock a user account")
    public void lock(@PathVariable String username) { userService.lockUser(username); }

    @PostMapping("/{username}/unlock")
    @PreAuthorize("@rbacService.hasAccess('user:unlock', authentication)")
    @Operation(summary = "Unlock a user account")
    public void unlock(@PathVariable String username) { userService.unlockUser(username); }
}