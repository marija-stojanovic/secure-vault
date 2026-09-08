package com.securevault.auth;

import com.securevault.policy.SecurityPolicyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SessionServiceTest {

    @Mock
    private SessionRepository sessionRepository;
    @Mock
    private SecurityPolicyRepository policyRepository;
    @Mock
    private TokenService tokenService;
    @Mock
    private Session currentSession;
    @Mock
    private Session relatedSession;

    private SessionService service;
    private Instant now;

    @BeforeEach
    void setUp() {
        now = Instant.parse("2026-09-04T12:00:00Z");
        service = new SessionService(
                sessionRepository,
                policyRepository,
                tokenService,
                Clock.fixed(now, ZoneOffset.UTC)
        );
    }

    @Test
    void logoutRevokesWholeTokenFamilyUsingRefreshToken() {
        byte[] refreshHash = new byte[] { 1, 2, 3 };
        when(tokenService.hash("refresh-token")).thenReturn(refreshHash);
        when(sessionRepository.findByRefreshTokenHash(refreshHash))
                .thenReturn(Optional.of(currentSession));
        when(currentSession.getTokenFamilyId()).thenReturn("family-1");
        when(sessionRepository.findAllByTokenFamilyId("family-1"))
                .thenReturn(List.of(currentSession, relatedSession));

        service.revokeByTokens(null, "refresh-token");

        verify(currentSession).revoke(now);
        verify(relatedSession).revoke(now);
        verify(sessionRepository, never()).findByAccessTokenHash(refreshHash);
    }

    @Test
    void logoutWithoutCookiesIsIdempotent() {
        service.revokeByTokens(null, null);

        verifyNoInteractions(sessionRepository, tokenService);
    }
}
