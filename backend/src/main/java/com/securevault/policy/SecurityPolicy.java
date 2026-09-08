package com.securevault.policy;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "security_policies")
public class SecurityPolicy {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "minimum_login_password_length", nullable = false,
            columnDefinition = "SMALLINT UNSIGNED NOT NULL DEFAULT 12")
    private short minimumLoginPasswordLength = 12;

    @Column(name = "minimum_master_password_length", nullable = false)
    private short minimumMasterPasswordLength;

    @Column(name = "secret_rotation_days", nullable = false)
    private short secretRotationDays;

    @Column(name = "access_token_lifetime_seconds", nullable = false)
    private int accessTokenLifetimeSeconds;

    @Column(name = "refresh_token_lifetime_seconds", nullable = false)
    private int refreshTokenLifetimeSeconds;

    @Column(name = "maximum_failed_login_attempts", nullable = false)
    private short maximumFailedLoginAttempts;

    @Column(name = "login_block_duration_seconds", nullable = false)
    private int loginBlockDurationSeconds;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private Instant updatedAt;

    protected SecurityPolicy() {
    }

    public short getMinimumMasterPasswordLength() {
        return minimumMasterPasswordLength;
    }

    public short getMinimumLoginPasswordLength() {
        return minimumLoginPasswordLength;
    }

    public short getSecretRotationDays() {
        return secretRotationDays;
    }

    public int getAccessTokenLifetimeSeconds() {
        return accessTokenLifetimeSeconds;
    }

    public int getRefreshTokenLifetimeSeconds() {
        return refreshTokenLifetimeSeconds;
    }

    public short getMaximumFailedLoginAttempts() {
        return maximumFailedLoginAttempts;
    }

    public int getLoginBlockDurationSeconds() {
        return loginBlockDurationSeconds;
    }

    public void updateManagedRules(
            short minimumLoginPasswordLength,
            short minimumMasterPasswordLength,
            short maximumFailedLoginAttempts,
            short secretRotationDays
    ) {
        this.minimumLoginPasswordLength = minimumLoginPasswordLength;
        this.minimumMasterPasswordLength = minimumMasterPasswordLength;
        this.maximumFailedLoginAttempts = maximumFailedLoginAttempts;
        this.secretRotationDays = secretRotationDays;
    }
}
