package com.securevault.audit;

import com.securevault.user.User;
import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class AuditService {
    private static final int CHAIN_ID = 1;
    private final AuditLogRepository logs;
    private final AuditChainStateRepository states;
    private final Clock clock;
    private final ObjectMapper objectMapper;

    public AuditService(AuditLogRepository logs, AuditChainStateRepository states, Clock clock,
                        ObjectMapper objectMapper) {
        this.logs = logs; this.states = states; this.clock = clock; this.objectMapper = objectMapper;
    }

    @Transactional
    public AuditLog record(User actor, String eventType, String targetType, Object targetId,
                           Map<String, ?> safeEventData) {
        return record(actor == null ? null : actor.getId(), eventType, targetType, targetId, safeEventData);
    }

    @Transactional
    public AuditLog record(Long actorId, String eventType, String targetType, Object targetId,
                           Map<String, ?> safeEventData) {
        AuditChainState state = states.findByIdForUpdate(CHAIN_ID)
                .orElseGet(() -> states.saveAndFlush(new AuditChainState(CHAIN_ID)));
        // MySQL TIMESTAMP(6) čuva mikrosekunde; hash mora koristiti potpuno istu preciznost.
        Instant occurredAt = Instant.now(clock).truncatedTo(ChronoUnit.MICROS);
        String data = canonicalJson(safeEventData == null ? Map.of() : safeEventData);
        String target = targetId == null ? null : targetId.toString();
        String ip = requestIp();
        byte[] previous = state.getLastHash() == null ? null : state.getLastHash().clone();
        byte[] hash = hash(canonicalRecord(actorId, eventType, targetType, target, ip, data, occurredAt, previous));
        AuditLog log = logs.saveAndFlush(new AuditLog(actorId, eventType, targetType, target,
                ip, data, occurredAt, previous, hash));
        state.advance(log, occurredAt);
        return log;
    }

    @Transactional(readOnly = true)
    public List<AuditLog> list() { return logs.findAllByOrderByIdDesc(); }

    @Transactional(readOnly = true)
    public IntegrityResult verifyIntegrity() {
        byte[] expectedPrevious = null;
        int checked = 0;
        for (AuditLog log : logs.findAllByOrderByIdAsc()) {
            checked++;
            if (!MessageDigest.isEqual(nullAsEmpty(expectedPrevious), nullAsEmpty(log.getPreviousHash())))
                return new IntegrityResult(false, checked, log.getId(), "previous_hash se ne podudara");
            byte[] calculated = hash(canonicalRecord(log.getActorUserId(), log.getEventType(),
                    log.getTargetType(), log.getTargetId(), log.getIpAddress(), log.getEventData(),
                    log.getOccurredAt(), log.getPreviousHash()));
            if (!MessageDigest.isEqual(calculated, log.getEntryHash()))
                return new IntegrityResult(false, checked, log.getId(), "entry_hash se ne podudara");
            expectedPrevious = log.getEntryHash();
        }
        AuditChainState state = states.findById(CHAIN_ID).orElse(null);
        if (state != null && !MessageDigest.isEqual(nullAsEmpty(expectedPrevious), nullAsEmpty(state.getLastHash())))
            return new IntegrityResult(false, checked, state.getLastAuditLogId(), "Vrh lanca se ne podudara");
        return new IntegrityResult(true, checked, null, "Lanac je ispravan");
    }

    private String canonicalJson(Map<String, ?> data) {
        StringJoiner json = new StringJoiner(",", "{", "}");
        new TreeMap<>(data).forEach((key, value) ->
                json.add("\"" + escapeJson(key) + "\":" + jsonValue(value)));
        return json.toString();
    }
    private String jsonValue(Object value) {
        if (value == null) return "null";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        return "\"" + escapeJson(value.toString()) + "\"";
    }
    private String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
    private String canonicalRecord(Long actor, String event, String type, String target, String ip,
                                   String data, Instant at, byte[] previous) {
        return value(actor) + "\n" + value(event) + "\n" + value(type) + "\n" + value(target) + "\n"
                + value(ip) + "\n" + normalizeStoredJson(data) + "\n" + at.toString() + "\n"
                + Base64.getEncoder().encodeToString(nullAsEmpty(previous));
    }
    @SuppressWarnings("unchecked")
    private String normalizeStoredJson(String json) {
        try { return canonicalJson(objectMapper.readValue(json, Map.class)); }
        catch (Exception e) { throw new IllegalStateException("Audit event_data nije ispravan JSON", e); }
    }
    private byte[] hash(String canonical) {
        try { return MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 nije dostupan", e); }
    }
    private String requestIp() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
            HttpServletRequest request = attrs.getRequest();
            String forwarded = request.getHeader("X-Forwarded-For");
            return forwarded == null || forwarded.isBlank() ? request.getRemoteAddr() : forwarded.split(",")[0].trim();
        }
        return null;
    }
    private static String value(Object value) { return value == null ? "" : value.toString(); }
    private static byte[] nullAsEmpty(byte[] bytes) { return bytes == null ? new byte[0] : bytes; }
    public record IntegrityResult(boolean valid, int checkedRecords, Long brokenAtId, String message) {}
}
