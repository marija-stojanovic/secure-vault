package com.securevault.auth;

import com.securevault.policy.SecurityPolicy;
import com.securevault.policy.SecurityPolicyRepository;
import com.securevault.user.User;
import com.securevault.user.UserStatus;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class SessionService {

    private final SessionRepository sessionRepository;
    private final SecurityPolicyRepository policyRepository;
    private final TokenService tokenService;
    private final Clock clock;

    public SessionService(
            SessionRepository sessionRepository,
            SecurityPolicyRepository policyRepository,
            TokenService tokenService,
            Clock clock
    ) {
        this.sessionRepository = sessionRepository;
        this.policyRepository = policyRepository;
        this.tokenService = tokenService;
        this.clock = clock;
    }

    @Transactional
    public IssuedSession create(User user, String ipAddress, String userAgent) {
        return create(user, UUID.randomUUID().toString(), ipAddress, userAgent);
    }

    @Transactional(readOnly = true)
    public Optional<User> authenticate(String rawAccessToken) {
        if (rawAccessToken == null || rawAccessToken.isBlank()) {
            return Optional.empty();
        }
        Instant now = Instant.now(clock);
        return sessionRepository.findByAccessTokenHash(tokenService.hash(rawAccessToken))
                .filter(session -> session.hasActiveAccessTokenAt(now))
                .map(Session::getUser)
                .filter(user -> user.getStatus() == UserStatus.ACTIVE);
    }

    @Transactional
    public IssuedSession rotate(String rawRefreshToken, String ipAddress, String userAgent) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw invalidSession();
        }

        Session current = sessionRepository
                .findByRefreshTokenHash(tokenService.hash(rawRefreshToken))
                .orElseThrow(this::invalidSession);
        Instant now = Instant.now(clock);

        if (current.getRotatedAt() != null) {
            revokeFamily(current.getTokenFamilyId(), now);
            throw invalidSession();
        }
        if (!current.isActiveAt(now) || current.getUser().getStatus() != UserStatus.ACTIVE) {
            current.revoke(now);
            throw invalidSession();
        }

        current.rotate(now);
        return create(
                current.getUser(),
                current.getTokenFamilyId(),
                ipAddress,
                userAgent
        );
    }

    @Transactional
    public void revokeByTokens(String rawAccessToken, String rawRefreshToken) {
        Optional<Session> session = findByRefreshToken(rawRefreshToken)
                .or(() -> findByAccessToken(rawAccessToken));
        session.ifPresent(found -> revokeFamily(found.getTokenFamilyId(), Instant.now(clock)));
    }

    @Transactional
    public void revokeAllForUser(long userId) {
        Instant now = Instant.now(clock);
        sessionRepository.findAllByUserId(userId).stream()
                .filter(session -> session.isActiveAt(now))
                .forEach(session -> session.revoke(now));
    }

    @Transactional(readOnly = true)
    public long countActiveForUser(long userId) {
        Instant now = Instant.now(clock);
        return sessionRepository.findAllByUserId(userId).stream()
                .filter(session -> session.isActiveAt(now))
                .count();
    }

    private IssuedSession create(
            User user,
            String tokenFamilyId,
            String ipAddress,
            String userAgent
    ) {
        SecurityPolicy policy = policyRepository.findFirstByOrderByIdAsc()
                .orElseThrow(() -> new IllegalStateException("Security policy is missing"));
        Instant now = Instant.now(clock);
        Instant accessExpiresAt = now.plusSeconds(policy.getAccessTokenLifetimeSeconds());
        Instant refreshExpiresAt = now.plusSeconds(policy.getRefreshTokenLifetimeSeconds());
        String accessToken = tokenService.generate();
        String refreshToken = tokenService.generate();

        sessionRepository.save(new Session(
                UUID.randomUUID().toString(),
                user,
                tokenService.hash(accessToken),
                tokenService.hash(refreshToken),
                tokenFamilyId,
                normalizeIp(ipAddress),
                truncate(userAgent, 500),
                accessExpiresAt,
                refreshExpiresAt
        ));

        return new IssuedSession(
                accessToken,
                refreshToken,
                accessExpiresAt,
                refreshExpiresAt
        );
    }

    private void revokeFamily(String tokenFamilyId, Instant time) {
        sessionRepository.findAllByTokenFamilyId(tokenFamilyId)
                .forEach(session -> session.revoke(time));
    }

    private Optional<Session> findByAccessToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }
        return sessionRepository.findByAccessTokenHash(tokenService.hash(rawToken));
    }

    private Optional<Session> findByRefreshToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }
        return sessionRepository.findByRefreshTokenHash(tokenService.hash(rawToken));
    }

    private String normalizeIp(String ipAddress) {
        return truncate(ipAddress == null ? "unknown" : ipAddress, 45);
    }

    private String truncate(String value, int maximumLength) {
        if (value == null) {
            return null;
        }
        return value.length() <= maximumLength ? value : value.substring(0, maximumLength);
    }

    private AuthException invalidSession() {
        return new AuthException(HttpStatus.UNAUTHORIZED, "Sesija nije ispravna ili je istekla");
    }

    public record IssuedSession(
            String accessToken,
            String refreshToken,
            Instant accessExpiresAt,
            Instant refreshExpiresAt
    ) {
    }
}
