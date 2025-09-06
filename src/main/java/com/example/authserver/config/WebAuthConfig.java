package com.example.authserver.config;


import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.example.authserver.user.RegistrationService;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;

@Component
public class WebAuthConfig {

	@Value("${webauthn.display:display}")
	private String displayName;

	@Value("${webauthn.origin:localhost}")
	private Set<String> origins;
	
	
	private final RegistrationService registrationService;

    public WebAuthConfig(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }
	
	public RelyingParty create(String rpId) {
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
            .id(rpId)
            .name(displayName)
            .build();

        return RelyingParty.builder()
            .identity(rpIdentity)
            .credentialRepository(registrationService)
            .origins(origins)
            .build();
    }
}
