package com.securevault.honeypot;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "honeytokens")
public class Honeytoken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "decoy_name", nullable = false, length = 255)
    private String decoyName;

    @Lob
    @Column(name = "decoy_encrypted_blob", nullable = false, columnDefinition = "MEDIUMBLOB")
    private byte[] decoyEncryptedBlob;

    @Column(name = "fingerprint_hash", nullable = false, columnDefinition = "BINARY(32)", unique = true)
    private byte[] fingerprintHash;

    @Column(name = "active", nullable = false)
    private boolean active = true;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected Honeytoken() {
    }

    public Honeytoken(String decoyName, byte[] decoyEncryptedBlob, byte[] fingerprintHash) {
        this.decoyName = decoyName;
        this.decoyEncryptedBlob = decoyEncryptedBlob.clone();
        this.fingerprintHash = fingerprintHash.clone();
    }
}
