package com.securevault.gateway.intrusion;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.intrusion")
public record IntrusionProperties(
        long violationThreshold,
        long suspiciousInputThreshold,
        long invalidTokenThreshold,
        long invalidTokenCooldownSeconds,
        long detectionWindowSeconds,
        long blockDurationSeconds
) {
    public IntrusionProperties {
        if (violationThreshold < 1 || suspiciousInputThreshold < 1 || invalidTokenThreshold < 1
                || invalidTokenCooldownSeconds < 1
                || detectionWindowSeconds < 1 || blockDurationSeconds < 1) {
            throw new IllegalArgumentException("Intrusion detection vrijednosti moraju biti pozitivne");
        }
    }
}
