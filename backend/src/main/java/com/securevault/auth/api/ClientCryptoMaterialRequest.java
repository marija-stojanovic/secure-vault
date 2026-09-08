package com.securevault.auth.api;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

public record ClientCryptoMaterialRequest(
        @NotBlank String kdfSaltBase64,
        @Min(100000) @Max(2000000) int kdfIterations,
        @NotBlank String publicKeySpkiBase64,
        @NotBlank String encryptedPrivateKeyBase64,
        @NotBlank String privateKeyIvBase64
) {
}
