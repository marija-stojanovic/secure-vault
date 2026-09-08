package com.securevault.audit.api;

import com.securevault.audit.AuditService;
import com.securevault.audit.AuditLog;
import com.securevault.user.User;
import com.securevault.user.UserRepository;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin/audit")
public class AuditAdminController {
    private final AuditService audit;
    private final UserRepository users;
    public AuditAdminController(AuditService audit, UserRepository users) { this.audit = audit; this.users = users; }
    @GetMapping
    public ResponseEntity<List<AuditLogResponse>> list() {
        Map<Long, String> usernames = users.findAll().stream()
                .collect(Collectors.toMap(User::getId, User::getUsername));
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(audit.list().stream()
                .map(log -> AuditLogResponse.from(log, usernames.get(log.getActorUserId()), targetUsername(log, usernames)))
                .toList());
    }
    @GetMapping("/integrity")
    public ResponseEntity<AuditService.IntegrityResult> integrity() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(audit.verifyIntegrity());
    }

    private String targetUsername(AuditLog log, Map<Long, String> usernames) {
        if (!"USER".equals(log.getTargetType()) || log.getTargetId() == null) return null;
        try { return usernames.get(Long.parseLong(log.getTargetId())); }
        catch (NumberFormatException ignored) { return null; }
    }
}
