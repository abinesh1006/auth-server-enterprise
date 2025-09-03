package com.example.authserver.password;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.*;

public class PasswordAuthenticationConverter implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!PasswordGrantType.GRANT_TYPE.equals(grantType)) return null;
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        String mfa = request.getParameter("mfa_code");
        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        Set<String> scopes = new HashSet<>(); if (StringUtils.hasText(scope)) scopes.addAll(Arrays.asList(scope.split(" ")));
        Authentication clientPrincipal = (Authentication) request.getUserPrincipal();
        if (!(clientPrincipal instanceof OAuth2ClientAuthenticationToken)) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        return new PasswordAuthenticationToken(clientPrincipal, username, password, scopes, mfa, Map.of("username", username));
    }
}
