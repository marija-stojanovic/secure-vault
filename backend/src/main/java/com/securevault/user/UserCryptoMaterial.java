package com.securevault.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "user_crypto_material")
public class UserCryptoMaterial {

    @Id
    @Column(name = "user_id")
    private Long userId;

    @MapsId
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "kdf_algorithm", nullable = false, length = 30)
    private String kdfAlgorithm;

    @Column(name = "kdf_salt", nullable = false, length = 64)
    private byte[] kdfSalt;

    @Column(name = "kdf_iterations", nullable = false)
    private int kdfIterations;

    @Column(name = "public_key_algorithm", nullable = false, length = 30)
    private String publicKeyAlgorithm;

    @Column(name = "public_key_spki", nullable = false, columnDefinition = "MEDIUMBLOB")
    private byte[] publicKeySpki;

    @Column(name = "encrypted_private_key", nullable = false, columnDefinition = "MEDIUMBLOB")
    private byte[] encryptedPrivateKey;

    @Column(name = "private_key_iv", nullable = false, length = 32)
    private byte[] privateKeyIv;

    @Column(name = "private_key_algorithm", nullable = false, length = 30)
    private String privateKeyAlgorithm;

    @Column(name = "crypto_version", nullable = false)
    private short cryptoVersion;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private Instant updatedAt;

    protected UserCryptoMaterial() {
    }

    public UserCryptoMaterial(
            User user,
            String kdfAlgorithm,
            byte[] kdfSalt,
            int kdfIterations,
            String publicKeyAlgorithm,
            byte[] publicKeySpki,
            byte[] encryptedPrivateKey,
            byte[] privateKeyIv,
            String privateKeyAlgorithm,
            short cryptoVersion
    ) {
        this.user = user;
        this.kdfAlgorithm = kdfAlgorithm;
        this.kdfSalt = kdfSalt.clone();
        this.kdfIterations = kdfIterations;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.publicKeySpki = publicKeySpki.clone();
        this.encryptedPrivateKey = encryptedPrivateKey.clone();
        this.privateKeyIv = privateKeyIv.clone();
        this.privateKeyAlgorithm = privateKeyAlgorithm;
        this.cryptoVersion = cryptoVersion;
    }

    public Long getUserId() {
        return userId;
    }

    public String getKdfAlgorithm() {
        return kdfAlgorithm;
    }

    public byte[] getKdfSalt() {
        return kdfSalt.clone();
    }

    public int getKdfIterations() {
        return kdfIterations;
    }

    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public byte[] getPublicKeySpki() {
        return publicKeySpki.clone();
    }

    public byte[] getEncryptedPrivateKey() {
        return encryptedPrivateKey.clone();
    }

    public byte[] getPrivateKeyIv() {
        return privateKeyIv.clone();
    }

    public String getPrivateKeyAlgorithm() {
        return privateKeyAlgorithm;
    }

    public short getCryptoVersion() {
        return cryptoVersion;
    }
}
