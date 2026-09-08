package com.securevault.security;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "blocked_ip_addresses")
public class BlockedIpAddress {

    @Id
    @Column(name = "ip_address", length = 45, nullable = false)
    private String ipAddress;

    @Column(nullable = false, length = 500)
    private String reason;

    @Column(name = "blocked_until", nullable = false)
    private Instant blockedUntil;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected BlockedIpAddress() {
    }

    public String getIpAddress() { return ipAddress; }
    public String getReason() { return reason; }
    public Instant getBlockedUntil() { return blockedUntil; }
    public Instant getCreatedAt() { return createdAt; }
}
