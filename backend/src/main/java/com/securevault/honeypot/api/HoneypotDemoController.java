package com.securevault.honeypot.api;

import com.securevault.honeypot.HoneypotService;
import com.securevault.audit.AuditService;
import com.securevault.user.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HoneypotDemoController {

    private final HoneypotService service;
    private final AuditService audit;

    public HoneypotDemoController(HoneypotService service, AuditService audit) {
        this.service = service;
        this.audit = audit;
    }

    @GetMapping("/api/demo/honeypot/status")
    public Map<String, Object> status() {
        HoneypotService.HoneypotStatus status = service.status();
        return status.enabled()
                ? Map.of("enabled", true, "enabledUntil", status.enabledUntil().toString())
                : Map.of("enabled", false);
    }

    @GetMapping("/api/demo/honeypot/search")
    public ResponseEntity<?> search(
            @RequestParam(defaultValue = "") String q,
            @AuthenticationPrincipal User actor,
            HttpServletRequest request
    ) {
        HoneypotService.DemoSearchResult result = service.executeIsolatedDemoSearch(q, actor, request.getRemoteAddr());
        if (result.triggered()) {
            audit.record(actor, "HONEYTOKEN_ACCESSED", "HONEYTOKEN", null,
                    Map.of("matchCount", result.matchCount(), "response", "ACCOUNT_FROZEN"));
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "code", "HONEYTOKEN_TRIGGERED",
                    "error", "Detektovan je pristup zaštićenom demonstracionom zapisu. Nalog je zamrznut."
            ));
        }
        return ResponseEntity.ok(Map.of("matches", 0));
    }
}
