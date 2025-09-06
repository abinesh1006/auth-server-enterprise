package com.example.authserver.security;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import com.example.authserver.config.WebAuthConfig;
import com.example.authserver.security.webauthn.LoginResponse;
import com.example.authserver.security.webauthn.RegistrationResponse;
import com.example.authserver.user.RegistrationService;
import com.example.authserver.user.UserEntity;
import com.example.authserver.user.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AttestedCredentialData;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RegistrationExtensionInputs;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class WebAuthnService {

	private final WebAuthnRequestStore requestStore;
	private final WebAuthnLoginStore assertionStore;

	private final RegistrationService registrationService;
	private final WebAuthnCredentialRepository webAuthRepository;
	private final WebAuthConfig webAuthConfig;
	private final AuthenticationService authenticationService;
	private final UserRepository userRepository;

	public String fetchRegisterOptions(HttpServletRequest request) {

		String rpId = extractRpId(request);
		RelyingParty relyingParty = webAuthConfig.create(rpId);

		UserEntity user = (UserEntity) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

		Assert.notNull(user, "User must not be null");

		UserIdentity userIdentity = UserIdentity.builder()
				.name(user.getUsername())
				.displayName(user.getFullName())
				.id(textToBytes(user.getUsername())).build();

		StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder().user(userIdentity).build();

		PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = relyingParty
				.startRegistration(registrationOptions).toBuilder()
				.timeout(Optional.of(Duration.ofMinutes(5).toMillis()))
				.authenticatorSelection(
						AuthenticatorSelectionCriteria.builder().residentKey(ResidentKeyRequirement.REQUIRED) // Prefer
																												// resident
																												// keys
								.userVerification(UserVerificationRequirement.PREFERRED) // Prefer user verification
								.build())
				.attestation(AttestationConveyancePreference.DIRECT)
				.extensions(RegistrationExtensionInputs.builder().uvm().credProps(true).build())
				.excludeCredentials(Optional.of(new HashSet<>())).build();

		log.info("Storing request for user: {}", user.getUsername());
		requestStore.storeRequest(user.getUsername(), publicKeyCredentialCreationOptions);

		try {
			return publicKeyCredentialCreationOptions.toCredentialsCreateJson();
		} catch (JsonProcessingException e) {
			log.error(e.getMessage());
			return "";
		}

	}

	private ByteArray longToBytes(long x) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(x);
		return new ByteArray(buffer.array());
	}


	public String bytesToText(ByteArray byteArray) {
		return new String(byteArray.getBytes(), StandardCharsets.UTF_8);
	}

	public ByteArray textToBytes(String text) {
		return new ByteArray(text.getBytes(StandardCharsets.UTF_8));
	}
	public RegistrationResponse finishRegistartions(String credential, String deviceCode, String deviceName,
			String location, HttpServletRequest request) {
		try {
			String rpId = extractRpId(request);
			RelyingParty relyingParty = webAuthConfig.create(rpId);

			UserEntity user = (UserEntity) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

			PublicKeyCredentialCreationOptions createOptions = requestStore.getRequest(user.getUsername());

			Assert.notNull(createOptions, "Credential Registration has been expired! Please try again!");

			PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc = PublicKeyCredential
					.parseRegistrationResponseJson(credential);

			FinishRegistrationOptions options = FinishRegistrationOptions.builder().request(createOptions).response(pkc)
					.build();

			RegistrationResult result = relyingParty.finishRegistration(options);

			Optional<AttestedCredentialData> attestationData = pkc.getResponse().getAttestation().getAuthenticatorData()
					.getAttestedCredentialData();
			WebAuthnCredential credentialWebauth = WebAuthnCredential.builder().user(user)
					.credentialId(result.getKeyId().getId()).publicKeyCose(result.getPublicKeyCose())
					.signatureCount(result.getSignatureCount()).aaguid(attestationData.get().getAaguid())
					.attestationObject(pkc.getResponse().getAttestationObject())
					.clientDataJSON(pkc.getResponse().getClientDataJSON()).deviceCode(deviceCode).location(location)
					.userAgent(deviceName).build();

//			registrationService.getWebAuthRepository().save(credentialWebauth);
			webAuthRepository.save(credentialWebauth);

			return new RegistrationResponse(deviceCode, LocalDateTime.now(), "Device has been registered successfully");
		} catch (Exception e) {
			log.error(e.getMessage());
			return null;
		}
	}

	public boolean isReadyForLogin(String username) {
		Set<PublicKeyCredentialDescriptor> listOfcredentials = registrationService
				.getCredentialIdsForUsername(username);

		return listOfcredentials.isEmpty() ? false : true;
	}

	public String initLogin(String username, HttpServletRequest httpServletRequest) {
		try {
			String rpId = extractRpId(httpServletRequest);
			RelyingParty relyingParty = webAuthConfig.create(rpId);

			AssertionRequest request = relyingParty.startAssertion(StartAssertionOptions.builder().username(username)
					.timeout(Optional.of(Duration.ofMinutes(5).toMillis()))
					.userVerification(UserVerificationRequirement.REQUIRED).build());

			assertionStore.storeRequest(username, request);

			return request.toCredentialsGetJson();
		} catch (Exception e) {
			log.error(e.getMessage());
			return "";
		}

	}

	public LoginResponse finishLogin(String credential, String username, HttpServletRequest httpServletRequest) {
		try {
			String rpId = extractRpId(httpServletRequest);
			RelyingParty relyingParty = webAuthConfig.create(rpId);

			PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc = PublicKeyCredential
					.parseAssertionResponseJson(credential);

			AssertionRequest request = assertionStore.getRequest(username);

			Assert.notNull(request, "Login time expired!");

			AssertionResult result = relyingParty
					.finishAssertion(FinishAssertionOptions.builder().request(request).response(pkc).build());

			if (result.isSuccess()) {

				WebAuthnCredential auth = webAuthRepository.findByCredentialId(result.getCredential().getCredentialId())
						.orElseThrow(() -> new Exception("Auth failed"));

				auth.setSignatureCount(result.getSignatureCount());

				webAuthRepository.save(auth);

				return authenticationService.generateAuthForUser(auth.getUser());
			}
		} catch (Exception e) {
			log.error(e.getMessage());
			return null;
		}
		return null;
	}

	public boolean isMFAEnabled(String username) {
		Optional<UserEntity> user = userRepository.findByUsername(username);
		if (user.isPresent()) {
			return user.get().getIsMfaEnabled();
		}
		return false;
	}

	private String extractRpId(HttpServletRequest request) {
		String host = request.getServerName();
		return host;
	}

}