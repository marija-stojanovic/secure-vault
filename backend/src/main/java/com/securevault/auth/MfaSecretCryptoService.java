package com.securevault.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class MfaSecretCryptoService {

    private static final int IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private final SecretKeySpec encryptionKey;
    private final SecureRandom secureRandom;

    public MfaSecretCryptoService(
            @Value("${app.security.mfa-encryption-key-base64}") String encodedKey,
            SecureRandom secureRandom
    ) {
        byte[] key = Base64.getDecoder().decode(encodedKey);
        if (key.length != 32) {
            throw new IllegalArgumentException("MFA encryption key must contain 32 bytes");
        }
        this.encryptionKey = new SecretKeySpec(key, "AES");
        this.secureRandom = secureRandom;
    }

    public EncryptedSecret encrypt(byte[] plaintext) {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            return new EncryptedSecret(cipher.doFinal(plaintext), iv);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to encrypt MFA secret", exception);
        }
    }

    public byte[] decrypt(byte[] ciphertext, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to decrypt MFA secret", exception);
        }
    }

    public record EncryptedSecret(byte[] ciphertext, byte[] iv) {
        public EncryptedSecret {
            ciphertext = ciphertext.clone();
            iv = iv.clone();
        }
    }
}
