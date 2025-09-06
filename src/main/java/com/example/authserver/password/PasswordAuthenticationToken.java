package com.example.authserver.password;

import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

public class PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
	private static final long serialVersionUID = 1L;
	private final String username;
	private final String password;
	private final Set<String> scopes;

	public PasswordAuthenticationToken(Authentication clientPrincipal, String username, String password,
			Set<String> scopes, Map<String, Object> addl) {
		super(new AuthorizationGrantType(PasswordGrantType.GRANT_TYPE), clientPrincipal, addl);
		this.username = username;
		this.password = password;
		this.scopes = scopes;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public Set<String> getScopes() {
		return scopes;
	}
}