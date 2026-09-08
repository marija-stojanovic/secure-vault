package com.securevault.auth.api;

public record RegistrationResponse(
        long userId,
        String username,
        String status,
        String totpSecret,
        String totpProvisioningUri
) {
}
