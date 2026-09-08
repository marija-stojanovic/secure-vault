package com.securevault.honeypot;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;

import java.time.Instant;

@Entity
@Table(name = "honeypot_control")
public class HoneypotControl {

    @Id
    private Integer id;

    @Column(name = "enabled_until")
    private Instant enabledUntil;

    @Column(name = "enabled_by")
    private Long enabledBy;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected HoneypotControl() {
    }

    public HoneypotControl(int id) {
        this.id = id;
    }

    public boolean isEnabledAt(Instant now) {
        return enabledUntil != null && enabledUntil.isAfter(now);
    }

    public void enableUntil(Instant time, long administratorId) {
        this.enabledUntil = time;
        this.enabledBy = administratorId;
    }

    public void disable() {
        this.enabledUntil = null;
        this.enabledBy = null;
    }

    @PrePersist
    @PreUpdate
    void touch() {
        updatedAt = Instant.now();
    }

    public Instant getEnabledUntil() {
        return enabledUntil;
    }

    public Long getEnabledBy() {
        return enabledBy;
    }
}
