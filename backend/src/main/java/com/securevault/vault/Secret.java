package com.securevault.vault;

import com.securevault.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "secrets")
public class Secret {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_user_id", nullable = false)
    private User owner;

    @Column(name = "team_id")
    private Long teamId;

    @Column(name = "current_version_number", nullable = false)
    private int currentVersionNumber = 1;

    @Column(name = "rotation_due_at")
    private Instant rotationDueAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private Instant updatedAt;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    protected Secret() {
    }

    public Secret(User owner) {
        this.owner = owner;
    }

    public Long getId() {
        return id;
    }

    public User getOwner() {
        return owner;
    }

    public int getCurrentVersionNumber() {
        return currentVersionNumber;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getDeletedAt() {
        return deletedAt;
    }

    public Instant getRotationDueAt() {
        return rotationDueAt;
    }

    public void scheduleRotation(Instant rotationDueAt) {
        this.rotationDueAt = rotationDueAt;
    }

    public void advanceToVersion(int versionNumber) {
        if (versionNumber != currentVersionNumber + 1) {
            throw new IllegalArgumentException("Nova verzija mora slijediti trenutnu verziju");
        }
        this.currentVersionNumber = versionNumber;
    }

    public void softDelete(Instant deletedAt) {
        if (this.deletedAt == null) {
            this.deletedAt = deletedAt;
        }
    }
}
