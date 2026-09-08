package com.securevault.auth.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record OidcMfaRequest(
        @NotBlank
        @Pattern(regexp = "\\d{6}", message = "MFA kod mora sadržati šest cifara")
        String code
) {
}
