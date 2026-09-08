package com.securevault.admin.api;

import com.securevault.user.User;

import java.time.Instant;

public record AdminUserResponse(
        long id,
        String username,
        String email,
        String role,
        String status,
        boolean mfaEnabled,
        short failedLoginAttempts,
        Instant lockedUntil,
        long activeSessionCount
) {
    public static AdminUserResponse from(User user, long activeSessionCount) {
        return new AdminUserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole().name(),
                user.getStatus().name(),
                user.isMfaEnabled(),
                user.getFailedLoginAttempts(),
                user.getLockedUntil(),
                activeSessionCount
        );
    }
}
