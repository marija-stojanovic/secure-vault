package com.securevault.auth.api;

import java.time.Instant;

public record SessionResponse(Instant accessExpiresAt) {
}
