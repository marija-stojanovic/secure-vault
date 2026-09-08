package com.securevault.auth;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class MfaSecretCryptoServiceTest {

    @Test
    void encryptsAndDecryptsTotpSecretWithAesGcm() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        MfaSecretCryptoService service = new MfaSecretCryptoService(key, new SecureRandom());
        byte[] plaintext = "totp-secret".getBytes(StandardCharsets.UTF_8);

        MfaSecretCryptoService.EncryptedSecret encrypted = service.encrypt(plaintext);

        assertFalse(java.util.Arrays.equals(plaintext, encrypted.ciphertext()));
        assertArrayEquals(
                plaintext,
                service.decrypt(encrypted.ciphertext(), encrypted.iv())
        );
    }
}
