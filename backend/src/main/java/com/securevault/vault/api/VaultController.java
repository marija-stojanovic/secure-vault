package com.securevault.vault.api;

import com.securevault.auth.AuthException;
import com.securevault.audit.AuditService;
import com.securevault.user.User;
import com.securevault.user.UserCryptoMaterial;
import com.securevault.user.UserCryptoMaterialRepository;
import com.securevault.vault.VaultService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/vault")
public class VaultController {

    private final UserCryptoMaterialRepository cryptoMaterialRepository;
    private final VaultService vaultService;
    private final AuditService audit;

    public VaultController(
            UserCryptoMaterialRepository cryptoMaterialRepository,
            VaultService vaultService, AuditService audit
    ) {
        this.cryptoMaterialRepository = cryptoMaterialRepository;
        this.vaultService = vaultService;
        this.audit = audit;
    }

    @GetMapping("/crypto-material")
    public ResponseEntity<VaultCryptoMaterialResponse> cryptoMaterial(
            @AuthenticationPrincipal User user
    ) {
        UserCryptoMaterial material = cryptoMaterialRepository.findById(user.getId())
                .orElseThrow(() -> new AuthException(
                        HttpStatus.NOT_FOUND,
                        "Kriptografski materijal korisnika nije pronađen"
                ));
        audit.record(user, "VAULT_UNLOCK_MATERIAL_ACCESSED", "USER", user.getId(), Map.of());
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(VaultCryptoMaterialResponse.from(material));
    }

    @PostMapping("/secrets")
    public CreatedSecretResponse createSecret(
            @AuthenticationPrincipal User user,
            @Valid @RequestBody CreateSecretRequest request
    ) {
        CreatedSecretResponse result = vaultService.create(user, request);
        audit.record(user, "SECRET_CREATED", "SECRET", result.secretId(), Map.of("version", result.versionNumber()));
        return result;
    }

    @GetMapping("/secrets")
    public ResponseEntity<List<VaultSecretResponse>> secrets(
            @AuthenticationPrincipal User user
    ) {
        List<VaultSecretResponse> result = vaultService.listOwned(user);
        audit.record(user, "SECRETS_ACCESSED", "USER", user.getId(), Map.of("count", result.size()));
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(result);
    }

    @PutMapping("/secrets/{secretId}")
    public CreatedSecretResponse updateSecret(
            @PathVariable long secretId,
            @AuthenticationPrincipal User user,
            @Valid @RequestBody CreateSecretRequest request
    ) {
        CreatedSecretResponse result = vaultService.update(secretId, user, request);
        audit.record(user, "SECRET_UPDATED", "SECRET", secretId, Map.of("version", result.versionNumber()));
        return result;
    }

    @PutMapping("/secrets/{secretId}/rotate")
    public CreatedSecretResponse rotateSecret(
            @PathVariable long secretId,
            @AuthenticationPrincipal User user,
            @Valid @RequestBody CreateSecretRequest request
    ) {
        CreatedSecretResponse result = vaultService.update(secretId, user, request);
        audit.record(user, "SECRET_ROTATED", "SECRET", secretId,
                Map.of("version", result.versionNumber(), "previousShares", "REQUIRE_NEW_ENVELOPE"));
        return result;
    }

    @DeleteMapping("/secrets/{secretId}")
    public ResponseEntity<Void> deleteSecret(
            @PathVariable long secretId,
            @AuthenticationPrincipal User user
    ) {
        vaultService.delete(secretId, user);
        audit.record(user, "SECRET_DELETED", "SECRET", secretId, Map.of("deletion", "SOFT_DELETE"));
        return ResponseEntity.noContent().build();
    }
}
