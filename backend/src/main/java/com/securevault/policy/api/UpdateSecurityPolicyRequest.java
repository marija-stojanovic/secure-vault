package com.securevault.policy.api;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

public record UpdateSecurityPolicyRequest(
        @Min(8) @Max(128) short minimumLoginPasswordLength,
        @Min(12) @Max(128) short minimumMasterPasswordLength,
        @Min(3) @Max(20) short maximumFailedLoginAttempts,
        @Min(1) @Max(3650) short secretRotationDays
) {
}
