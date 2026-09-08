package com.securevault.audit;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_chain_state")
public class AuditChainState {
    @Id private Integer id;
    @Column(name = "last_audit_log_id") private Long lastAuditLogId;
    @Column(name = "last_hash", columnDefinition = "binary(32)") private byte[] lastHash;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;
    protected AuditChainState() {}
    public AuditChainState(int id) { this.id = id; this.updatedAt = Instant.now(); }
    public void advance(AuditLog log, Instant now) {
        this.lastAuditLogId = log.getId(); this.lastHash = log.getEntryHash(); this.updatedAt = now;
    }
    public Long getLastAuditLogId() { return lastAuditLogId; }
    public byte[] getLastHash() { return lastHash; }
}
