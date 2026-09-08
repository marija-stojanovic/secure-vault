package com.securevault.security.api;

import com.securevault.security.SecurityAlertService;
import com.securevault.audit.AuditService;
import com.securevault.user.User;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin/security-alerts")
public class SecurityAlertAdminController {

    private final SecurityAlertService service;
    private final AuditService audit;

    public SecurityAlertAdminController(SecurityAlertService service, AuditService audit) {
        this.service = service;
        this.audit = audit;
    }

    @GetMapping
    public ResponseEntity<List<SecurityAlertResponse>> list() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.list());
    }

    @PostMapping("/{alertId}/acknowledge")
    public SecurityAlertResponse acknowledge(
            @PathVariable long alertId,
            @AuthenticationPrincipal User administrator
    ) {
        SecurityAlertResponse result = service.acknowledge(alertId, administrator);
        audit.record(administrator, "SECURITY_ALERT_ACKNOWLEDGED", "SECURITY_ALERT", alertId, Map.of());
        return result;
    }
}
