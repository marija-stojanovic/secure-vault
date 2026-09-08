package com.securevault.vault.api;

import java.time.Instant;

public record VaultSecretResponse(
        long secretId,
        int versionNumber,
        String encryptedBlobBase64,
        String encryptionIvBase64,
        String encryptionAlgorithm,
        String wrappedDataKeyBase64,
        String wrappingAlgorithm,
        Instant createdAt,
        Instant updatedAt,
        Instant rotationDueAt
) {
}
