package com.securevault.user;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserTest {

    @Test
    void newUserStartsPendingWithoutMfaOrFailedLogins() {
        User user = new User(
                "developer",
                "developer@example.com",
                "$argon2id$example-hash",
                UserRole.DEVELOPER
        );

        assertEquals(UserStatus.PENDING, user.getStatus());
        assertFalse(user.isMfaEnabled());
        assertEquals(0, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
        assertNull(user.getLastLoginAt());
    }

    @Test
    void successfulLoginClearsTemporaryLockAndFailedAttempts() {
        User user = new User(
                "teamlead",
                "teamlead@example.com",
                "$argon2id$example-hash",
                UserRole.TEAM_LEAD
        );
        Instant lockExpiration = Instant.parse("2026-08-21T12:30:00Z");
        Instant loginTime = Instant.parse("2026-08-21T12:31:00Z");

        user.recordFailedLoginAttempt();
        user.lockUntil(lockExpiration);
        user.recordSuccessfulLogin(loginTime);

        assertEquals(0, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
        assertEquals(loginTime, user.getLastLoginAt());
    }

    @Test
    void userCanBeActivatedAndMfaEnabled() {
        User user = new User(
                "admin",
                "admin@example.com",
                "$argon2id$example-hash",
                UserRole.ADMIN
        );

        user.changeStatus(UserStatus.ACTIVE);
        user.enableMfa();

        assertEquals(UserStatus.ACTIVE, user.getStatus());
        assertTrue(user.isMfaEnabled());
    }
}
