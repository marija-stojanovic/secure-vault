package com.securevault.audit;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_logs")
public class AuditLog {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "actor_user_id") private Long actorUserId;
    @Column(name = "event_type", nullable = false, length = 100) private String eventType;
    @Column(name = "target_type", length = 80) private String targetType;
    @Column(name = "target_id", length = 100) private String targetId;
    @Column(name = "ip_address", length = 45) private String ipAddress;
    @Column(name = "event_data", nullable = false, columnDefinition = "json") private String eventData;
    @Column(name = "occurred_at", nullable = false) private Instant occurredAt;
    @Column(name = "previous_hash", columnDefinition = "binary(32)") private byte[] previousHash;
    @Column(name = "entry_hash", nullable = false, columnDefinition = "binary(32)") private byte[] entryHash;

    protected AuditLog() {}
    public AuditLog(Long actorUserId, String eventType, String targetType, String targetId,
                    String ipAddress, String eventData, Instant occurredAt,
                    byte[] previousHash, byte[] entryHash) {
        this.actorUserId = actorUserId; this.eventType = eventType; this.targetType = targetType;
        this.targetId = targetId; this.ipAddress = ipAddress; this.eventData = eventData;
        this.occurredAt = occurredAt; this.previousHash = previousHash; this.entryHash = entryHash;
    }
    public Long getId() { return id; }
    public Long getActorUserId() { return actorUserId; }
    public String getEventType() { return eventType; }
    public String getTargetType() { return targetType; }
    public String getTargetId() { return targetId; }
    public String getIpAddress() { return ipAddress; }
    public String getEventData() { return eventData; }
    public Instant getOccurredAt() { return occurredAt; }
    public byte[] getPreviousHash() { return previousHash; }
    public byte[] getEntryHash() { return entryHash; }
}
