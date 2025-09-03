package com.example.authserver.mfa;

import com.example.authserver.user.UserEntity;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity @Table(name="user_mfa")
@Getter @Setter
public class UserMfaEntity {
    @Id
    private UUID userId;

    @OneToOne @MapsId @JoinColumn(name="user_id")
    private UserEntity user;

    private String secret;
    private LocalDateTime createdAt;
}
