package com.example.authserver.mfa;

import com.example.authserver.user.UserEntity;
import com.example.authserver.user.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

@Service
public class MfaService {
    private final UserRepository users;
    private final UserMfaRepository mfas;

    @Value("${app.mfa.issuer}")
    private String issuer;

    public MfaService(UserRepository users, UserMfaRepository mfas) {
        this.users = users; this.mfas = mfas;
    }

    @Transactional
    public String enroll(String username) {
        UserEntity user = users.findByUsername(username).orElseThrow();
        String secret = TotpService.generateSecret();
        UserMfaEntity mfa = new UserMfaEntity();
        mfa.setUser(user); mfa.setSecret(secret); mfa.setCreatedAt(LocalDateTime.now());
        mfas.save(mfa);
        // Return provisioning URI (can be rendered as QR by clients)
        String label = URLEncoder.encode(issuer + ":" + user.getEmail(), StandardCharsets.UTF_8);
        String iss = URLEncoder.encode(issuer, StandardCharsets.UTF_8);
        return "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + iss + "&algorithm=SHA1&digits=6&period=30";
    }

    public boolean verify(String username, String code) {
        var user = users.findByUsername(username).orElseThrow();
        var mfa = mfas.findByUserId(user.getId()).orElseThrow();
        return TotpService.verifyCode(mfa.getSecret(), code);
    }
}
