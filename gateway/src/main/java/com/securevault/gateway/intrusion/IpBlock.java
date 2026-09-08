package com.securevault.gateway.intrusion;

import java.time.Instant;

public record IpBlock(String reason, Instant blockedUntil) {
}
