package com.securevault.security.api;

import com.securevault.security.SecurityAlert;

import java.time.Instant;

public record SecurityAlertResponse(
        long id,
        Long userId,
        String username,
        String alertType,
        String severity,
        String ipAddress,
        String description,
        Long acknowledgedBy,
        Instant acknowledgedAt,
        Instant createdAt
) {
    public static SecurityAlertResponse from(SecurityAlert alert) {
        return new SecurityAlertResponse(
                alert.getId(),
                alert.getUser() == null ? null : alert.getUser().getId(),
                alert.getUser() == null ? null : alert.getUser().getUsername(),
                alert.getAlertType(),
                alert.getSeverity().name(),
                alert.getIpAddress(),
                alert.getDescription(),
                alert.getAcknowledgedBy() == null ? null : alert.getAcknowledgedBy().getId(),
                alert.getAcknowledgedAt(),
                alert.getCreatedAt()
        );
    }
}
