package com.securevault.auth.oidc;

import com.securevault.auth.AuthCookieService;
import com.securevault.auth.MfaChallengeService;
import com.securevault.user.User;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OidcAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final OidcLoginService oidcLoginService;
    private final MfaChallengeService mfaChallengeService;
    private final AuthCookieService cookieService;
    private final OidcOnboardingService onboardingService;
    private final String frontendRedirectUri;

    public OidcAuthenticationSuccessHandler(
            OidcLoginService oidcLoginService,
            MfaChallengeService mfaChallengeService,
            AuthCookieService cookieService,
            OidcOnboardingService onboardingService,
            @Value("${app.oidc.frontend-redirect-uri:https://localhost:5173/}") String frontendRedirectUri
    ) {
        this.oidcLoginService = oidcLoginService;
        this.mfaChallengeService = mfaChallengeService;
        this.cookieService = cookieService;
        this.onboardingService = onboardingService;
        this.frontendRedirectUri = frontendRedirectUri;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {
        try {
            if (!(authentication.getPrincipal() instanceof OidcUser oidcUser)) {
                throw new OidcLoginException("invalid-provider", "OIDC identitet nije dostupan");
            }

            OidcLoginService.LoginResult login = oidcLoginService.resolveGoogleUser(
                    oidcUser.getIssuer().toString(),
                    oidcUser.getSubject(),
                    oidcUser.getEmail(),
                    Boolean.TRUE.equals(oidcUser.getEmailVerified())
            );
            User user = login.user();

            if (login.onboardingRequired()) {
                OidcOnboardingService.IssuedOnboarding onboarding = onboardingService.issue(user.getId());
                invalidateTemporarySpringSession(request);
                cookieService.writeOidcOnboarding(response, onboarding.token(), onboarding.expiresAt());
                response.sendRedirect(frontendRedirectUri + "?oidc=setup");
                return;
            }

            MfaChallengeService.IssuedChallenge challenge =
                    mfaChallengeService.issue(user.getId());

            invalidateTemporarySpringSession(request);
            cookieService.clearSession(response);
            cookieService.writeOidcMfaChallenge(
                    response,
                    challenge.token(),
                    challenge.expiresAt()
            );
            response.sendRedirect(frontendRedirectUri + "?oidc=mfa");
        } catch (OidcLoginException exception) {
            invalidateTemporarySpringSession(request);
            response.sendRedirect(frontendRedirectUri + "?oidc=error&reason=" + exception.getCode());
        }
    }

    private void invalidateTemporarySpringSession(HttpServletRequest request) {
        HttpSession temporarySession = request.getSession(false);
        if (temporarySession != null) {
            temporarySession.invalidate();
        }
    }
}
