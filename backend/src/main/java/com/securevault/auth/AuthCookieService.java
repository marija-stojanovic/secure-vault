package com.securevault.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

@Service
public class AuthCookieService {

    public static final String ACCESS_COOKIE = "SV_ACCESS";
    public static final String REFRESH_COOKIE = "SV_REFRESH";
    public static final String OIDC_ONBOARDING_COOKIE = "SV_OIDC_ONBOARDING";
    public static final String OIDC_MFA_COOKIE = "SV_OIDC_MFA";
    private static final String ACCESS_PATH = "/api";
    private static final String REFRESH_PATH = "/api/auth";
    private static final String LEGACY_REFRESH_PATH = "/api/auth/refresh";

    private final boolean secure;
    private final Clock clock;

    public AuthCookieService(@Value("${app.security.cookie-secure}") boolean secure, Clock clock) {
        this.secure = secure;
        this.clock = clock;
    }

    public void writeSession(HttpServletResponse response, SessionService.IssuedSession session) {
        response.addHeader(HttpHeaders.SET_COOKIE, buildCookie(
                ACCESS_COOKIE,
                session.accessToken(),
                ACCESS_PATH,
                session.accessExpiresAt()
        ).toString());
        // Uklanja cookie iz ranije verzije aplikacije koja je koristila užu putanju.
        response.addHeader(HttpHeaders.SET_COOKIE,
                expiredCookie(REFRESH_COOKIE, LEGACY_REFRESH_PATH).toString());
        response.addHeader(HttpHeaders.SET_COOKIE, buildCookie(
                REFRESH_COOKIE,
                session.refreshToken(),
                REFRESH_PATH,
                session.refreshExpiresAt()
        ).toString());
    }

    public void clearSession(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, expiredCookie(ACCESS_COOKIE, ACCESS_PATH).toString());
        response.addHeader(HttpHeaders.SET_COOKIE, expiredCookie(REFRESH_COOKIE, REFRESH_PATH).toString());
        response.addHeader(HttpHeaders.SET_COOKIE,
                expiredCookie(REFRESH_COOKIE, LEGACY_REFRESH_PATH).toString());
    }

    public void writeOidcOnboarding(HttpServletResponse response, String token, Instant expiresAt) {
        response.addHeader(HttpHeaders.SET_COOKIE, buildCookie(
                OIDC_ONBOARDING_COOKIE,
                token,
                "/api/auth/oidc/setup",
                expiresAt
        ).toString());
    }

    public void clearOidcOnboarding(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                expiredCookie(OIDC_ONBOARDING_COOKIE, "/api/auth/oidc/setup").toString());
    }

    public void writeOidcMfaChallenge(HttpServletResponse response, String token, Instant expiresAt) {
        response.addHeader(HttpHeaders.SET_COOKIE, buildCookie(
                OIDC_MFA_COOKIE,
                token,
                "/api/auth/oidc/mfa",
                expiresAt
        ).toString());
    }

    public void clearOidcMfaChallenge(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                expiredCookie(OIDC_MFA_COOKIE, "/api/auth/oidc/mfa").toString());
    }

    public String read(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        return Arrays.stream(cookies)
                .filter(cookie -> cookieName.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    private ResponseCookie buildCookie(String name, String value, String path, Instant expiresAt) {
        Duration lifetime = Duration.between(Instant.now(clock), expiresAt);
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(secure)
                .sameSite("Strict")
                .path(path)
                .maxAge(lifetime.isNegative() ? Duration.ZERO : lifetime)
                .build();
    }

    private ResponseCookie expiredCookie(String name, String path) {
        return ResponseCookie.from(name, "")
                .httpOnly(true)
                .secure(secure)
                .sameSite("Strict")
                .path(path)
                .maxAge(Duration.ZERO)
                .build();
    }
}
