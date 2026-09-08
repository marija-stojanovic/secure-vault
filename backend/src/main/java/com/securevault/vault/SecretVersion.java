package com.securevault.vault;

import com.securevault.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "secret_versions")
public class SecretVersion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "secret_id", nullable = false)
    private Secret secret;

    @Column(name = "version_number", nullable = false)
    private int versionNumber;

    @Column(name = "encrypted_blob", nullable = false, columnDefinition = "MEDIUMBLOB")
    private byte[] encryptedBlob;

    @Column(name = "encryption_iv", nullable = false, length = 32)
    private byte[] encryptionIv;

    @Column(name = "encryption_algorithm", nullable = false, length = 30)
    private String encryptionAlgorithm;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "created_by", nullable = false)
    private User createdBy;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected SecretVersion() {
    }

    public SecretVersion(
            Secret secret,
            int versionNumber,
            byte[] encryptedBlob,
            byte[] encryptionIv,
            String encryptionAlgorithm,
            User createdBy
    ) {
        this.secret = secret;
        this.versionNumber = versionNumber;
        this.encryptedBlob = encryptedBlob.clone();
        this.encryptionIv = encryptionIv.clone();
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.createdBy = createdBy;
    }

    public Long getId() {
        return id;
    }

    public int getVersionNumber() {
        return versionNumber;
    }

    public Secret getSecret() {
        return secret;
    }

    public byte[] getEncryptedBlob() {
        return encryptedBlob.clone();
    }

    public byte[] getEncryptionIv() {
        return encryptionIv.clone();
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }
}
