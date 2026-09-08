package com.securevault.auth.api;

import com.securevault.user.User;

import java.time.Instant;

public record AuthenticatedUserResponse(
        long id,
        String username,
        String email,
        String role,
        Instant accessExpiresAt
) {
    public static AuthenticatedUserResponse from(User user, Instant accessExpiresAt) {
        return new AuthenticatedUserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole().name(),
                accessExpiresAt
        );
    }
}
