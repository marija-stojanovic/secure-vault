package com.securevault.admin.api;

import com.securevault.admin.AdminUserService;
import com.securevault.audit.AuditService;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.securevault.user.User;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

    private final AdminUserService adminUserService;
    private final AuditService audit;

    public AdminUserController(AdminUserService adminUserService, AuditService audit) {
        this.adminUserService = adminUserService;
        this.audit = audit;
    }

    @GetMapping
    public ResponseEntity<List<AdminUserResponse>> users() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(adminUserService.listUsers());
    }

    @PostMapping("/{userId}/promote-team-lead")
    public AdminUserResponse promoteToTeamLead(@PathVariable long userId, @AuthenticationPrincipal User administrator) {
        AdminUserResponse result = adminUserService.promoteToTeamLead(userId);
        audit.record(administrator, "USER_ROLE_CHANGED", "USER", userId, Map.of("newRole", "TEAM_LEAD"));
        return result;
    }

    @PostMapping("/{userId}/demote-developer")
    public AdminUserResponse demoteToDeveloper(@PathVariable long userId, @AuthenticationPrincipal User administrator) {
        AdminUserResponse result = adminUserService.demoteToDeveloper(userId);
        audit.record(administrator, "USER_ROLE_CHANGED", "USER", userId, Map.of("newRole", "DEVELOPER"));
        return result;
    }

    @PostMapping("/{userId}/freeze")
    public AdminUserResponse freeze(@PathVariable long userId, @AuthenticationPrincipal User administrator) {
        AdminUserResponse result = adminUserService.freeze(userId, administrator);
        audit.record(administrator, "USER_FROZEN", "USER", userId, Map.of()); return result;
    }

    @PostMapping("/{userId}/unfreeze")
    public AdminUserResponse unfreeze(@PathVariable long userId, @AuthenticationPrincipal User administrator) {
        AdminUserResponse result = adminUserService.unfreeze(userId, administrator);
        audit.record(administrator, "USER_UNFROZEN", "USER", userId, Map.of()); return result;
    }

    @PostMapping("/{userId}/disable")
    public AdminUserResponse disable(@PathVariable long userId, @AuthenticationPrincipal User administrator) {
        AdminUserResponse result = adminUserService.disable(userId, administrator);
        audit.record(administrator, "USER_DISABLED", "USER", userId, Map.of()); return result;
    }

    @PostMapping("/{userId}/unlock")
    public AdminUserResponse unlock(@PathVariable long userId, @AuthenticationPrincipal User administrator) {
        AdminUserResponse result = adminUserService.unlock(userId, administrator);
        audit.record(administrator, "USER_LOGIN_UNLOCKED", "USER", userId, Map.of()); return result;
    }

    @PostMapping("/{userId}/revoke-sessions")
    public AdminUserResponse revokeSessions(@PathVariable long userId, @AuthenticationPrincipal User administrator) {
        AdminUserResponse result = adminUserService.revokeSessions(userId, administrator);
        audit.record(administrator, "USER_SESSIONS_REVOKED", "USER", userId, Map.of()); return result;
    }
}
