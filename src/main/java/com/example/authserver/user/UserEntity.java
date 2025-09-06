package com.example.authserver.user;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity @Table(name = "users")
@Getter @Setter
public class UserEntity {
    @Id @GeneratedValue
    private UUID id;

    @Column(unique = true, nullable = false) private String username;
    @Column(unique = true, nullable = false) private String email;
    @Column(nullable = false) private String password;
    @Column(nullable = false) private String fullName;
    private String firstName;
    private String lastName;
    private Double ratePerHour;
    private String profileFileName;
    private LocalDateTime passwordUpdateDate;
    private String passwordToken;
    private LocalDateTime passwordTokenExpiry;
    private Boolean isActive = Boolean.TRUE;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastLoginDateTime;
    private Integer loginAttempt = 0;
    private Boolean isBlocked = Boolean.FALSE;
    private LocalDateTime blockedDate;
    private Boolean isMfaEnabled = Boolean.TRUE;
}
