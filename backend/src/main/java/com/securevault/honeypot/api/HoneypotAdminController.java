package com.securevault.honeypot.api;

import com.securevault.honeypot.HoneypotService;
import com.securevault.audit.AuditService;
import com.securevault.user.User;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
@RequestMapping("/api/admin/honeypot")
public class HoneypotAdminController {

    private final HoneypotService service;
    private final AuditService audit;

    public HoneypotAdminController(HoneypotService service, AuditService audit) {
        this.service = service;
        this.audit = audit;
    }

    @GetMapping("/status")
    public HoneypotService.HoneypotStatus status() {
        return service.status();
    }

    @PutMapping("/status")
    public HoneypotService.HoneypotStatus configure(
            @Valid @RequestBody ConfigureHoneypotRequest request,
            @AuthenticationPrincipal User administrator
    ) {
        HoneypotService.HoneypotStatus result = service.configure(request.enabled(), request.durationMinutes(), administrator);
        audit.record(administrator, request.enabled() ? "HONEYPOT_DEMO_ENABLED" : "HONEYPOT_DEMO_DISABLED",
                "HONEYPOT_CONTROL", 1, Map.of("durationMinutes", request.durationMinutes()));
        return result;
    }
}
