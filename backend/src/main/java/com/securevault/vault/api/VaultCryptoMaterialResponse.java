package com.securevault.vault.api;

import com.securevault.user.UserCryptoMaterial;

import java.util.Base64;

public record VaultCryptoMaterialResponse(
        String kdfAlgorithm,
        String kdfSaltBase64,
        int kdfIterations,
        String publicKeyAlgorithm,
        String publicKeySpkiBase64,
        String encryptedPrivateKeyBase64,
        String privateKeyIvBase64,
        String privateKeyAlgorithm,
        short cryptoVersion
) {
    public static VaultCryptoMaterialResponse from(UserCryptoMaterial material) {
        Base64.Encoder encoder = Base64.getEncoder();
        return new VaultCryptoMaterialResponse(
                material.getKdfAlgorithm(),
                encoder.encodeToString(material.getKdfSalt()),
                material.getKdfIterations(),
                material.getPublicKeyAlgorithm(),
                encoder.encodeToString(material.getPublicKeySpki()),
                encoder.encodeToString(material.getEncryptedPrivateKey()),
                encoder.encodeToString(material.getPrivateKeyIv()),
                material.getPrivateKeyAlgorithm(),
                material.getCryptoVersion()
        );
    }
}
