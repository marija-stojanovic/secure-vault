package com.securevault.auth.oidc;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OidcAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final String frontendRedirectUri;

    public OidcAuthenticationFailureHandler(
            @Value("${app.oidc.frontend-redirect-uri:https://localhost:5173/}") String frontendRedirectUri
    ) {
        this.frontendRedirectUri = frontendRedirectUri;
    }

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException {
        HttpSession temporarySession = request.getSession(false);
        if (temporarySession != null) {
            temporarySession.invalidate();
        }
        response.sendRedirect(frontendRedirectUri + "?oidc=error&reason=provider-error");
    }
}
