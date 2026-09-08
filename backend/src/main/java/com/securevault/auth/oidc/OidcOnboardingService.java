package com.securevault.auth.oidc;

import com.securevault.auth.AuthException;
import com.securevault.auth.TokenService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class OidcOnboardingService {

    private static final long TOKEN_LIFETIME_SECONDS = 600;

    private final TokenService tokenService;
    private final Clock clock;
    private final Map<String, PendingOnboarding> pending = new ConcurrentHashMap<>();

    public OidcOnboardingService(TokenService tokenService, Clock clock) {
        this.tokenService = tokenService;
        this.clock = clock;
    }

    public IssuedOnboarding issue(long userId) {
        Instant now = Instant.now(clock);
        pending.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));

        String rawToken = tokenService.generate();
        Instant expiresAt = now.plusSeconds(TOKEN_LIFETIME_SECONDS);
        pending.put(tokenService.hashAsKey(rawToken), new PendingOnboarding(userId, expiresAt));
        return new IssuedOnboarding(rawToken, expiresAt);
    }

    public long consume(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw invalidToken();
        }
        PendingOnboarding onboarding = pending.remove(tokenService.hashAsKey(rawToken));
        if (onboarding == null || !onboarding.expiresAt().isAfter(Instant.now(clock))) {
            throw invalidToken();
        }
        return onboarding.userId();
    }

    private AuthException invalidToken() {
        return new AuthException(HttpStatus.UNAUTHORIZED, "Google registracija je istekla; prijavi se ponovo Google nalogom");
    }

    private record PendingOnboarding(long userId, Instant expiresAt) {
    }

    public record IssuedOnboarding(String token, Instant expiresAt) {
    }
}
