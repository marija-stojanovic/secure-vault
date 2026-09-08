package com.securevault.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(max = 100)
    @Column(name = "username", nullable = false, length = 100, unique = true)
    private String username;

    @NotBlank
    @Email
    @Size(max = 254)
    @Column(name = "email", nullable = false, length = 254, unique = true)
    private String email;

    @Size(max = 255)
    @Column(name = "login_password_hash", length = 255)
    private String loginPasswordHash;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(
            name = "role",
            nullable = false,
            columnDefinition = "ENUM('ADMIN','TEAM_LEAD','DEVELOPER')"
    )
    private UserRole role;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(
            name = "status",
            nullable = false,
            columnDefinition = "ENUM('PENDING','ACTIVE','FROZEN','DISABLED')"
    )
    private UserStatus status = UserStatus.PENDING;

    @Column(name = "mfa_enabled", nullable = false)
    private boolean mfaEnabled;

    @Column(name = "failed_login_attempts", nullable = false)
    private short failedLoginAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private Instant updatedAt;

    protected User() {
        // JPA zahtijeva konstruktor bez argumenata.
    }

    public User(String username, String email, String loginPasswordHash, UserRole role) {
        this.username = username;
        this.email = email;
        this.loginPasswordHash = loginPasswordHash;
        this.role = role;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getLoginPasswordHash() {
        return loginPasswordHash;
    }

    public UserRole getRole() {
        return role;
    }

    public UserStatus getStatus() {
        return status;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled;
    }

    public short getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public Instant getLastLoginAt() {
        return lastLoginAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void changeStatus(UserStatus status) {
        this.status = status;
    }

    public void changeRole(UserRole role) {
        this.role = role;
    }

    public void enableMfa() {
        this.mfaEnabled = true;
    }

    public void recordFailedLoginAttempt() {
        if (failedLoginAttempts < Short.MAX_VALUE) {
            failedLoginAttempts++;
        }
    }

    public void lockUntil(Instant lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    public boolean isLockedAt(Instant time) {
        return lockedUntil != null && lockedUntil.isAfter(time);
    }

    public void recordSuccessfulLogin(Instant loginTime) {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
        this.lastLoginAt = loginTime;
    }

    public void clearLoginLock() {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
    }
}
