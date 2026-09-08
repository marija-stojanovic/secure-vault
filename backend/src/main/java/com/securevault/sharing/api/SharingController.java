package com.securevault.sharing.api;

import com.securevault.sharing.SharingService;
import com.securevault.audit.AuditService;
import com.securevault.user.User;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/sharing")
public class SharingController {

    private final SharingService sharingService;
    private final AuditService audit;

    public SharingController(SharingService sharingService, AuditService audit) {
        this.sharingService = sharingService;
        this.audit = audit;
    }

    @GetMapping("/developers")
    public ResponseEntity<List<ShareRecipientResponse>> developers(
            @AuthenticationPrincipal User teamLead
    ) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(sharingService.listDevelopers(teamLead));
    }

    @PostMapping("/secrets/{secretId}")
    public ResponseEntity<Void> share(
            @PathVariable long secretId,
            @AuthenticationPrincipal User teamLead,
            @Valid @RequestBody ShareSecretRequest request
    ) {
        sharingService.share(secretId, teamLead, request);
        audit.record(teamLead, "SECRET_SHARED", "SECRET", secretId,
                Map.of("recipientUserId", request.recipientUserId(), "version", request.versionNumber()));
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/secrets/{secretId}/recipients")
    public ResponseEntity<List<SharedRecipientResponse>> recipients(
            @PathVariable long secretId,
            @AuthenticationPrincipal User teamLead
    ) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(sharingService.listRecipients(secretId, teamLead));
    }

    @DeleteMapping("/secrets/{secretId}/recipients/{recipientId}")
    public ResponseEntity<Void> revoke(
            @PathVariable long secretId,
            @PathVariable long recipientId,
            @AuthenticationPrincipal User teamLead
    ) {
        sharingService.revoke(secretId, recipientId, teamLead);
        audit.record(teamLead, "SECRET_SHARE_REVOKED", "SECRET", secretId,
                Map.of("recipientUserId", recipientId));
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/received")
    public ResponseEntity<List<ReceivedSecretResponse>> received(
            @AuthenticationPrincipal User developer
    ) {
        List<ReceivedSecretResponse> result = sharingService.listReceived(developer);
        audit.record(developer, "SHARED_SECRETS_ACCESSED", "USER", developer.getId(), Map.of("count", result.size()));
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(result);
    }
}
