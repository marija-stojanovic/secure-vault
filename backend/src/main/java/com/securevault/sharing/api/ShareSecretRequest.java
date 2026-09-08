package com.securevault.sharing.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

public record ShareSecretRequest(
        @Positive long recipientUserId,
        @Positive int versionNumber,
        @NotBlank @Size(max = 1_024) String wrappedDataKeyBase64
) {
}
