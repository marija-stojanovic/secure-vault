package com.securevault.vault.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateSecretRequest(
        @NotBlank @Size(max = 1_500_000) String encryptedBlobBase64,
        @NotBlank @Size(max = 64) String encryptionIvBase64,
        @NotBlank @Size(max = 1_024) String wrappedDataKeyBase64
) {
}
