package com.example.authserver.security;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.authserver.user.UserEntity;
import com.yubico.webauthn.data.ByteArray;

@Repository
public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredential, Long> {

	List<WebAuthnCredential> findByUserId(Long userId);

	List<WebAuthnCredential> findAllByUser(UserEntity user);

	List<WebAuthnCredential> findByUserUsername(String username);

	Optional<WebAuthnCredential> findByCredentialId(ByteArray credentialId);

	List<WebAuthnCredential> findAllByCredentialId(ByteArray bytes);

	List<WebAuthnCredential> findAllByUserUsername(String username);
}
