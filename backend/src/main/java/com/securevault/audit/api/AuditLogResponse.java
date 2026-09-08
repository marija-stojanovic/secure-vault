package com.securevault.audit.api;

import com.securevault.audit.AuditLog;
import java.time.Instant;
import java.util.Base64;

public record AuditLogResponse(Long id, Long actorUserId, String actorUsername,
                               String eventType, String targetType,
                               String targetId, String targetUsername, String ipAddress, String eventData,
                               Instant occurredAt, String previousHash, String entryHash) {
    public static AuditLogResponse from(AuditLog log, String actorUsername, String targetUsername) {
        Base64.Encoder encoder = Base64.getEncoder();
        return new AuditLogResponse(log.getId(), log.getActorUserId(), actorUsername, log.getEventType(),
                log.getTargetType(), log.getTargetId(), targetUsername, log.getIpAddress(), log.getEventData(), log.getOccurredAt(),
                log.getPreviousHash() == null ? null : encoder.encodeToString(log.getPreviousHash()),
                encoder.encodeToString(log.getEntryHash()));
    }
}
