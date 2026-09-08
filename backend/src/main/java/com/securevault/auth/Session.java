package com.securevault.auth;

import com.securevault.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "sessions")
public class Session {

    @Id
    @Column(name = "id", nullable = false, length = 36)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "access_token_hash", nullable = false, length = 32, unique = true)
    private byte[] accessTokenHash;

    @Column(name = "refresh_token_hash", nullable = false, length = 32, unique = true)
    private byte[] refreshTokenHash;

    @Column(name = "token_family_id", nullable = false, length = 36)
    private String tokenFamilyId;

    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "access_expires_at", nullable = false)
    private Instant accessExpiresAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "rotated_at")
    private Instant rotatedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected Session() {
    }

    public Session(
            String id,
            User user,
            byte[] accessTokenHash,
            byte[] refreshTokenHash,
            String tokenFamilyId,
            String ipAddress,
            String userAgent,
            Instant accessExpiresAt,
            Instant expiresAt
    ) {
        this.id = id;
        this.user = user;
        this.accessTokenHash = accessTokenHash.clone();
        this.refreshTokenHash = refreshTokenHash.clone();
        this.tokenFamilyId = tokenFamilyId;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.accessExpiresAt = accessExpiresAt;
        this.expiresAt = expiresAt;
    }

    public User getUser() {
        return user;
    }

    public String getTokenFamilyId() {
        return tokenFamilyId;
    }

    public Instant getAccessExpiresAt() {
        return accessExpiresAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getRotatedAt() {
        return rotatedAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public boolean isActiveAt(Instant now) {
        return revokedAt == null && rotatedAt == null && expiresAt.isAfter(now);
    }

    public boolean hasActiveAccessTokenAt(Instant now) {
        return isActiveAt(now) && accessExpiresAt.isAfter(now);
    }

    public void rotate(Instant time) {
        this.rotatedAt = time;
    }

    public void revoke(Instant time) {
        this.revokedAt = time;
    }
}
