package com.securevault.auth;

import com.securevault.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "user_mfa")
public class UserMfa {

    @Id
    @Column(name = "user_id")
    private Long userId;

    @MapsId
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "encrypted_totp_secret", nullable = false, length = 512)
    private byte[] encryptedTotpSecret;

    @Column(name = "encryption_iv", nullable = false, length = 32)
    private byte[] encryptionIv;

    @Column(name = "confirmed_at")
    private Instant confirmedAt;

    @Column(name = "last_used_time_step")
    private Long lastUsedTimeStep;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected UserMfa() {
    }

    public UserMfa(User user, byte[] encryptedTotpSecret, byte[] encryptionIv) {
        this.user = user;
        this.encryptedTotpSecret = encryptedTotpSecret.clone();
        this.encryptionIv = encryptionIv.clone();
    }

    public User getUser() {
        return user;
    }

    public byte[] getEncryptedTotpSecret() {
        return encryptedTotpSecret.clone();
    }

    public byte[] getEncryptionIv() {
        return encryptionIv.clone();
    }

    public Instant getConfirmedAt() {
        return confirmedAt;
    }

    public Long getLastUsedTimeStep() {
        return lastUsedTimeStep;
    }

    public void confirm(Instant time, long usedTimeStep) {
        this.confirmedAt = time;
        this.lastUsedTimeStep = usedTimeStep;
    }

    public void recordUsedTimeStep(long usedTimeStep) {
        this.lastUsedTimeStep = usedTimeStep;
    }
}
