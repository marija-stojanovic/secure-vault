package com.securevault.policy.api;

import com.securevault.policy.SecurityPolicyService;
import com.securevault.audit.AuditService;
import com.securevault.user.User;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import java.util.Map;

@RestController
public class SecurityPolicyController {

    private final SecurityPolicyService service;
    private final AuditService audit;

    public SecurityPolicyController(SecurityPolicyService service, AuditService audit) {
        this.service = service;
        this.audit = audit;
    }

    @GetMapping("/api/security-policy/public")
    public ResponseEntity<SecurityPolicyResponse> publicPolicy() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.current());
    }

    @GetMapping("/api/admin/security-policy")
    public ResponseEntity<SecurityPolicyResponse> adminPolicy() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.current());
    }

    @PutMapping("/api/admin/security-policy")
    public SecurityPolicyResponse update(@Valid @RequestBody UpdateSecurityPolicyRequest request,
                                         @AuthenticationPrincipal User administrator) {
        SecurityPolicyResponse result = service.update(request);
        audit.record(administrator, "SECURITY_POLICY_UPDATED", "SECURITY_POLICY", 1,
                Map.of("minimumLoginPasswordLength", result.minimumLoginPasswordLength(),
                        "minimumMasterPasswordLength", result.minimumMasterPasswordLength(),
                        "maximumFailedLoginAttempts", result.maximumFailedLoginAttempts(),
                        "secretRotationDays", result.secretRotationDays()));
        return result;
    }
}
