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
@Table(name = "secret_key_envelopes")
public class SecretKeyEnvelope {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "secret_version_id", nullable = false)
    private SecretVersion secretVersion;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "recipient_user_id", nullable = false)
    private User recipient;

    @Column(name = "wrapped_data_key", nullable = false, columnDefinition = "MEDIUMBLOB")
    private byte[] wrappedDataKey;

    @Column(name = "wrapping_algorithm", nullable = false, length = 30)
    private String wrappingAlgorithm;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "shared_by_user_id", nullable = false)
    private User sharedBy;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    protected SecretKeyEnvelope() {
    }

    public SecretKeyEnvelope(
            SecretVersion secretVersion,
            User recipient,
            byte[] wrappedDataKey,
            String wrappingAlgorithm,
            User sharedBy
    ) {
        this.secretVersion = secretVersion;
        this.recipient = recipient;
        this.wrappedDataKey = wrappedDataKey.clone();
        this.wrappingAlgorithm = wrappingAlgorithm;
        this.sharedBy = sharedBy;
    }

    public byte[] getWrappedDataKey() {
        return wrappedDataKey.clone();
    }

    public String getWrappingAlgorithm() {
        return wrappingAlgorithm;
    }

    public SecretVersion getSecretVersion() {
        return secretVersion;
    }

    public User getRecipient() {
        return recipient;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public void replaceAndReactivate(byte[] wrappedDataKey, User sharedBy) {
        this.wrappedDataKey = wrappedDataKey.clone();
        this.sharedBy = sharedBy;
        this.revokedAt = null;
    }

    public void revoke(Instant revokedAt) {
        if (this.revokedAt == null) {
            this.revokedAt = revokedAt;
        }
    }
}
