package com.securevault.auth.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record MfaLoginRequest(
        @NotBlank String mfaChallenge,
        @NotBlank @Pattern(regexp = "\\d{6}") String code
) {
}
