package com.example.authserver.password;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import java.util.Map;
import java.util.Set;

public class PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private final String username; private final String password; private final Set<String> scopes; private final String mfaCode;
    public PasswordAuthenticationToken(Authentication clientPrincipal, String username, String password, Set<String> scopes, String mfaCode, Map<String,Object> addl) {
        super(new AuthorizationGrantType(PasswordGrantType.GRANT_TYPE), clientPrincipal, addl);
        this.username=username; this.password=password; this.scopes=scopes; this.mfaCode=mfaCode;
    }
    public String getUsername(){return username;} public String getPassword(){return password;} public Set<String> getScopes(){return scopes;} public String getMfaCode(){return mfaCode;}
}
