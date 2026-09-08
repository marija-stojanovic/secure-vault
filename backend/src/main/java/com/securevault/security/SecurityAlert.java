package com.securevault.security;

import com.securevault.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "security_alerts")
public class SecurityAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "alert_type", nullable = false, length = 80)
    private String alertType;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false,
            columnDefinition = "ENUM('LOW','MEDIUM','HIGH','CRITICAL')")
    private SecurityAlertSeverity severity;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "description", nullable = false, length = 1000)
    private String description;

    @ManyToOne
    @JoinColumn(name = "acknowledged_by")
    private User acknowledgedBy;

    @Column(name = "acknowledged_at")
    private Instant acknowledgedAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected SecurityAlert() {
    }

    public SecurityAlert(User user, String alertType, SecurityAlertSeverity severity,
                         String ipAddress, String description) {
        this.user = user;
        this.alertType = alertType;
        this.severity = severity;
        this.ipAddress = ipAddress;
        this.description = description;
    }

    public void acknowledge(User administrator, Instant time) {
        if (acknowledgedAt == null) {
            acknowledgedBy = administrator;
            acknowledgedAt = time;
        }
    }

    public Long getId() { return id; }
    public User getUser() { return user; }
    public String getAlertType() { return alertType; }
    public SecurityAlertSeverity getSeverity() { return severity; }
    public String getIpAddress() { return ipAddress; }
    public String getDescription() { return description; }
    public User getAcknowledgedBy() { return acknowledgedBy; }
    public Instant getAcknowledgedAt() { return acknowledgedAt; }
    public Instant getCreatedAt() { return createdAt; }
}
