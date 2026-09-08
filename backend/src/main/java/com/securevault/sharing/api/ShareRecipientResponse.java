package com.securevault.sharing.api;

public record ShareRecipientResponse(
        long userId,
        String username,
        String email,
        String publicKeyAlgorithm,
        String publicKeySpkiBase64
) {
}
