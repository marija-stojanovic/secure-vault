package com.securevault.auth.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record MfaConfirmationRequest(
        @NotBlank @Size(max = 100) String username,
        @NotBlank @Pattern(regexp = "\\d{6}") String code
) {
}
