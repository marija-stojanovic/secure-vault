package com.securevault.sharing.api;

import java.time.Instant;

public record ReceivedSecretResponse(
        long secretId,
        long ownerUserId,
        String ownerUsername,
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
