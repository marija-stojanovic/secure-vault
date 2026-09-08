package com.securevault.auth;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthCookieServiceTest {

    @Test
    void writesHttpOnlySecureStrictCookies() {
        Instant now = Instant.parse("2026-08-21T12:00:00Z");
        AuthCookieService service = new AuthCookieService(
                true,
                Clock.fixed(now, ZoneOffset.UTC)
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        SessionService.IssuedSession session = new SessionService.IssuedSession(
                "access-token",
                "refresh-token",
                now.plusSeconds(900),
                now.plusSeconds(604800)
        );

        service.writeSession(response, session);

        assertEquals(3, response.getHeaders("Set-Cookie").size());
        response.getHeaders("Set-Cookie").forEach(header -> {
            assertTrue(header.contains("HttpOnly"));
            assertTrue(header.contains("Secure"));
            assertTrue(header.contains("SameSite=Strict"));
        });
        assertTrue(response.getHeaders("Set-Cookie").stream()
                .anyMatch(header -> header.contains("SV_ACCESS=access-token")
                        && header.contains("Path=/api")));
        assertTrue(response.getHeaders("Set-Cookie").stream()
                .anyMatch(header -> header.contains("SV_REFRESH=refresh-token")
                        && header.contains("Path=/api/auth")));
    }

    @Test
    void writesRestrictedOidcMfaCookie() {
        Instant now = Instant.parse("2026-08-21T12:00:00Z");
        AuthCookieService service = new AuthCookieService(
                true,
                Clock.fixed(now, ZoneOffset.UTC)
        );
        MockHttpServletResponse response = new MockHttpServletResponse();

        service.writeOidcMfaChallenge(response, "mfa-token", now.plusSeconds(300));

        String header = response.getHeader("Set-Cookie");
        assertTrue(header.contains("SV_OIDC_MFA=mfa-token"));
        assertTrue(header.contains("Path=/api/auth/oidc/mfa"));
        assertTrue(header.contains("HttpOnly"));
        assertTrue(header.contains("Secure"));
        assertTrue(header.contains("SameSite=Strict"));
    }
}
