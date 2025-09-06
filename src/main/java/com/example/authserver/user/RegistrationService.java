package com.example.authserver.user;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.example.authserver.security.WebAuthnCredential;
import com.example.authserver.security.WebAuthnCredentialRepository;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RegistrationService implements CredentialRepository {

	private final UserRepository userRepository;

	private final WebAuthnCredentialRepository webAuthRepository;

	@Override
	public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {

		List<WebAuthnCredential> creds = webAuthRepository.findAllByUserUsername(username);

		return creds.stream()
				.map(credential -> PublicKeyCredentialDescriptor.builder().id(credential.getCredentialId()).build())
				.collect(Collectors.toSet());

	}

	@Override
	public Optional<ByteArray> getUserHandleForUsername(String username) {

		Optional<UserEntity> user = userRepository.findByUsername(username);

		if (user.isPresent()) {
			return Optional.of(textToBytes(user.get().getUsername()));
		}

		return Optional.empty();
	}

	@Override
	public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {

		String userName = bytesToText(userHandle);

		Optional<UserEntity> user = userRepository.findByUsername(userName);

		if (user.isPresent()) {
			return Optional.of(user.get().getUsername());
		}

		return Optional.empty();
	}

	@Override
	public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {

		Optional<WebAuthnCredential> auth = webAuthRepository.findByCredentialId(credentialId);

		return auth.map(credential -> RegisteredCredential.builder().credentialId(credential.getCredentialId())
				.userHandle(textToBytes(credential.getUser().getUsername())).publicKeyCose(credential.getPublicKeyCose())
				.signatureCount(credential.getSignatureCount()).build());
	}

	public Optional<RegisteredCredential> lookup(ByteArray credentialId) {

		Optional<WebAuthnCredential> auth = webAuthRepository.findByCredentialId(credentialId);

		return auth.map(credential -> RegisteredCredential.builder().credentialId(credential.getCredentialId())
				.userHandle(textToBytes(credential.getUser().getUsername())).publicKeyCose(credential.getPublicKeyCose())
				.signatureCount(credential.getSignatureCount()).build());
	}

	@Override
	public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {

		List<WebAuthnCredential> auth = webAuthRepository.findAllByCredentialId(credentialId);

		return auth.stream().map(credential -> RegisteredCredential.builder().credentialId(credential.getCredentialId())
				.userHandle(textToBytes(credential.getUser().getUsername())).publicKeyCose(credential.getPublicKeyCose())
				.signatureCount(credential.getSignatureCount()).build()).collect(Collectors.toSet());

	}

	public ByteArray longToBytes(long x) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(x);
		return new ByteArray(buffer.array());
	}

	public long bytesToLong(ByteArray byteArray) {
		ByteBuffer buffer = ByteBuffer.wrap(byteArray.getBytes());
		return buffer.getLong();
	}

	public String bytesToText(ByteArray byteArray) {
		return new String(byteArray.getBytes(), StandardCharsets.UTF_8);
	}

	public ByteArray textToBytes(String text) {
		return new ByteArray(text.getBytes(StandardCharsets.UTF_8));
	}
}