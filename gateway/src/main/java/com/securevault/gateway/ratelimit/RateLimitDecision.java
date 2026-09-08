package com.securevault.gateway.ratelimit;

public record RateLimitDecision(boolean allowed, long remaining, long retryAfterSeconds) {
}
