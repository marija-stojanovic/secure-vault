package com.securevault.auth.api;

import java.time.Instant;

public record PasswordLoginResponse(
        boolean mfaRequired,
        String mfaChallenge,
        Instant expiresAt
) {
}
