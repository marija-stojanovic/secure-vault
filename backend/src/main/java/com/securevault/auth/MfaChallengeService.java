package com.securevault.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class MfaChallengeService {

    private static final int MAXIMUM_MFA_ATTEMPTS = 5;

    private final ConcurrentHashMap<String, Challenge> challenges = new ConcurrentHashMap<>();
    private final TokenService tokenService;
    private final Clock clock;
    private final int lifetimeSeconds;

    public MfaChallengeService(
            TokenService tokenService,
            Clock clock,
            @Value("${app.security.mfa-challenge-lifetime-seconds}") int lifetimeSeconds
    ) {
        this.tokenService = tokenService;
        this.clock = clock;
        this.lifetimeSeconds = lifetimeSeconds;
    }

    public IssuedChallenge issue(long userId) {
        removeExpired();
        String rawToken = tokenService.generate();
        Instant expiresAt = Instant.now(clock).plusSeconds(lifetimeSeconds);
        challenges.put(tokenService.hashAsKey(rawToken), new Challenge(userId, expiresAt));
        return new IssuedChallenge(rawToken, expiresAt);
    }

    public long requireUserId(String rawToken) {
        Challenge challenge = requireChallenge(rawToken);
        return challenge.userId();
    }

    public void recordFailure(String rawToken) {
        String key = tokenService.hashAsKey(rawToken);
        Challenge challenge = requireChallenge(rawToken);
        if (challenge.failedAttempts().incrementAndGet() >= MAXIMUM_MFA_ATTEMPTS) {
            challenges.remove(key, challenge);
        }
    }

    public void consume(String rawToken) {
        String key = tokenService.hashAsKey(rawToken);
        Challenge challenge = requireChallenge(rawToken);
        if (!challenges.remove(key, challenge)) {
            throw invalidChallenge();
        }
    }

    private Challenge requireChallenge(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw invalidChallenge();
        }
        String key = tokenService.hashAsKey(rawToken);
        Challenge challenge = challenges.get(key);
        if (challenge == null || !challenge.expiresAt().isAfter(Instant.now(clock))) {
            challenges.remove(key);
            throw invalidChallenge();
        }
        return challenge;
    }

    private void removeExpired() {
        Instant now = Instant.now(clock);
        challenges.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
    }

    private AuthException invalidChallenge() {
        return new AuthException(HttpStatus.UNAUTHORIZED, "MFA zahtjev nije ispravan ili je istekao");
    }

    private record Challenge(long userId, Instant expiresAt, AtomicInteger failedAttempts) {
        private Challenge(long userId, Instant expiresAt) {
            this(userId, expiresAt, new AtomicInteger());
        }
    }

    public record IssuedChallenge(String token, Instant expiresAt) {
    }
}
