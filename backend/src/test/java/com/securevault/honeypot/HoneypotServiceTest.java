package com.securevault.honeypot;

import com.securevault.auth.AuthException;
import com.securevault.auth.SessionService;
import com.securevault.security.SecurityAlert;
import com.securevault.security.SecurityAlertRepository;
import com.securevault.user.User;
import com.securevault.user.UserRepository;
import com.securevault.user.UserRole;
import com.securevault.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HoneypotServiceTest {

    private final HoneypotControlRepository controls = mock(HoneypotControlRepository.class);
    private final SecurityAlertRepository alerts = mock(SecurityAlertRepository.class);
    private final UserRepository users = mock(UserRepository.class);
    private final SessionService sessions = mock(SessionService.class);
    private final IsolatedHoneypotQueryExecutor queryExecutor = mock(IsolatedHoneypotQueryExecutor.class);
    private final Clock clock = Clock.fixed(Instant.parse("2026-09-04T16:00:00Z"), ZoneOffset.UTC);
    private final HoneypotService service = new HoneypotService(controls, alerts, users, sessions, queryExecutor, clock);
    private final HoneypotControl control = new HoneypotControl(1);

    @BeforeEach
    void setUp() {
        when(controls.findById(1)).thenReturn(Optional.of(control));
    }

    @Test
    void disabledDemoEndpointCannotExecuteQuery() {
        User actor = user(7L, UserRole.DEVELOPER);

        assertThrows(AuthException.class,
                () -> service.executeIsolatedDemoSearch("anything", actor, "127.0.0.1"));
    }

    @Test
    void honeytokenMatchFreezesActorRevokesSessionsAndCreatesAlert() {
        User admin = user(1L, UserRole.ADMIN);
        User actor = user(7L, UserRole.DEVELOPER);
        service.configure(true, 5, admin);
        when(users.findById(7L)).thenReturn(Optional.of(actor));
        when(queryExecutor.unsafeSearch("' OR 1=1 -- ")).thenReturn(3);

        HoneypotService.DemoSearchResult result =
                service.executeIsolatedDemoSearch("' OR 1=1 -- ", actor, "127.0.0.1");

        assertEquals(true, result.triggered());
        assertEquals(3, result.matchCount());
        assertEquals(UserStatus.FROZEN, actor.getStatus());
        verify(sessions).revokeAllForUser(7L);
        verify(alerts).save(any(SecurityAlert.class));
    }

    private User user(long id, UserRole role) {
        User user = new User("user" + id, "user" + id + "@example.com", "hash", role);
        ReflectionTestUtils.setField(user, "id", id);
        user.changeStatus(UserStatus.ACTIVE);
        return user;
    }
}
