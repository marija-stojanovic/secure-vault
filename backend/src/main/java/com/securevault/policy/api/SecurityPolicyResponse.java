package com.securevault.policy.api;

import com.securevault.policy.SecurityPolicy;

public record SecurityPolicyResponse(
        short minimumLoginPasswordLength,
        short minimumMasterPasswordLength,
        short maximumFailedLoginAttempts,
        short secretRotationDays
) {
    public static SecurityPolicyResponse from(SecurityPolicy policy) {
        return new SecurityPolicyResponse(
                policy.getMinimumLoginPasswordLength(),
                policy.getMinimumMasterPasswordLength(),
                policy.getMaximumFailedLoginAttempts(),
                policy.getSecretRotationDays()
        );
    }
}
