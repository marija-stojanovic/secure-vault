package com.securevault.auth.api;

import com.securevault.auth.AuthCookieService;
import com.securevault.audit.AuditService;
import com.securevault.auth.LoginService;
import com.securevault.auth.RegistrationService;
import com.securevault.auth.SessionService;
import com.securevault.auth.oidc.OidcOnboardingService;
import com.securevault.user.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final RegistrationService registrationService;
    private final LoginService loginService;
    private final SessionService sessionService;
    private final AuthCookieService cookieService;
    private final OidcOnboardingService oidcOnboardingService;
    private final AuditService audit;

    public AuthController(
            RegistrationService registrationService,
            LoginService loginService,
            SessionService sessionService,
            AuthCookieService cookieService,
            OidcOnboardingService oidcOnboardingService,
            AuditService audit
    ) {
        this.registrationService = registrationService;
        this.loginService = loginService;
        this.sessionService = sessionService;
        this.cookieService = cookieService;
        this.oidcOnboardingService = oidcOnboardingService;
        this.audit = audit;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegistrationResponse register(@Valid @RequestBody RegistrationRequest request) {
        RegistrationResponse result = registrationService.register(request);
        audit.record(result.userId(), "USER_REGISTERED", "USER", result.userId(), Map.of("method", "PASSWORD"));
        return result;
    }

    @PostMapping("/oidc/setup")
    public RegistrationResponse setupOidcAccount(
            @Valid @RequestBody ClientCryptoMaterialRequest cryptoMaterial,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse
    ) {
        String token = cookieService.read(servletRequest, AuthCookieService.OIDC_ONBOARDING_COOKIE);
        long userId = oidcOnboardingService.consume(token);
        RegistrationResponse result = registrationService.setupOidcUser(userId, cryptoMaterial);
        audit.record(userId, "USER_REGISTERED", "USER", userId, Map.of("method", "GOOGLE_OIDC"));
        cookieService.clearOidcOnboarding(servletResponse);
        return result;
    }

    @PostMapping("/oidc/mfa")
    public AuthenticatedUserResponse loginOidcMfa(
            @Valid @RequestBody OidcMfaRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse
    ) {
        String challenge = cookieService.read(
                servletRequest,
                AuthCookieService.OIDC_MFA_COOKIE
        );
        LoginService.CompletedLogin completed = loginService.verifyMfa(
                new MfaLoginRequest(challenge, request.code()),
                servletRequest.getRemoteAddr(),
                servletRequest.getHeader("User-Agent")
        );
        cookieService.clearOidcMfaChallenge(servletResponse);
        cookieService.writeSession(servletResponse, completed.session());
        audit.record(completed.user(), "LOGIN_SUCCEEDED", "SESSION", null, Map.of("method", "GOOGLE_OIDC_MFA"));
        return AuthenticatedUserResponse.from(
                completed.user(),
                completed.session().accessExpiresAt()
        );
    }

    @PostMapping("/mfa/confirm")
    public MessageResponse confirmMfa(@Valid @RequestBody MfaConfirmationRequest request) {
        registrationService.confirmMfa(request);
        audit.record((Long) null, "MFA_CONFIRMED", "USER", request.username(), Map.of());
        return new MessageResponse("MFA je potvrđen i nalog je aktivan");
    }

    @PostMapping("/login/password")
    public PasswordLoginResponse loginPassword(@Valid @RequestBody PasswordLoginRequest request) {
        try {
            return loginService.verifyPassword(request);
        } catch (RuntimeException exception) {
            audit.record((Long) null, "LOGIN_FAILED", "USER", request.username(), Map.of("stage", "PASSWORD"));
            throw exception;
        }
    }

    @PostMapping("/login/mfa")
    public AuthenticatedUserResponse loginMfa(
            @Valid @RequestBody MfaLoginRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse
    ) {
        LoginService.CompletedLogin completed;
        try {
            completed = loginService.verifyMfa(request, servletRequest.getRemoteAddr(),
                    servletRequest.getHeader("User-Agent"));
        } catch (RuntimeException exception) {
            audit.record((Long) null, "LOGIN_FAILED", "MFA", null, Map.of("stage", "TOTP"));
            throw exception;
        }
        cookieService.writeSession(servletResponse, completed.session());
        audit.record(completed.user(), "LOGIN_SUCCEEDED", "SESSION", null, Map.of("method", "PASSWORD_MFA"));
        return AuthenticatedUserResponse.from(
                completed.user(),
                completed.session().accessExpiresAt()
        );
    }

    @PostMapping("/refresh")
    public SessionResponse refresh(
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse
    ) {
        String refreshToken = cookieService.read(
                servletRequest,
                AuthCookieService.REFRESH_COOKIE
        );
        SessionService.IssuedSession session = sessionService.rotate(
                refreshToken,
                servletRequest.getRemoteAddr(),
                servletRequest.getHeader("User-Agent")
        );
        cookieService.writeSession(servletResponse, session);
        return new SessionResponse(session.accessExpiresAt());
    }

    @PostMapping("/logout")
    public MessageResponse logout(
            @AuthenticationPrincipal User user,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse
    ) {
        String accessToken = cookieService.read(
                servletRequest,
                AuthCookieService.ACCESS_COOKIE
        );
        String refreshToken = cookieService.read(
                servletRequest,
                AuthCookieService.REFRESH_COOKIE
        );
        sessionService.revokeByTokens(accessToken, refreshToken);
        audit.record(user, "LOGOUT", "SESSION", null, Map.of());
        cookieService.clearSession(servletResponse);
        return new MessageResponse("Odjava je uspješna");
    }

    @GetMapping("/me")
    public AuthenticatedUserResponse me(@AuthenticationPrincipal User user) {
        return AuthenticatedUserResponse.from(user, null);
    }

    @GetMapping("/csrf")
    public CsrfTokenResponse csrf(CsrfToken token) {
        return new CsrfTokenResponse(token.getToken());
    }
}
