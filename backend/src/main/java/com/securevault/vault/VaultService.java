package com.securevault.vault;

import com.securevault.auth.AuthException;
import com.securevault.user.User;
import com.securevault.vault.api.CreateSecretRequest;
import com.securevault.vault.api.CreatedSecretResponse;
import com.securevault.vault.api.VaultSecretResponse;
import com.securevault.policy.SecurityPolicyRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.List;
import java.time.Clock;
import java.time.Instant;

@Service
public class VaultService {

    private static final String ENCRYPTION_ALGORITHM = "AES-256-GCM";
    private static final String WRAPPING_ALGORITHM = "RSA-OAEP-3072";
    private static final int AES_GCM_IV_BYTES = 12;
    private static final int RSA_3072_CIPHERTEXT_BYTES = 384;
    private static final int MAXIMUM_ENCRYPTED_BLOB_BYTES = 1_048_576;

    private final SecretRepository secretRepository;
    private final SecretVersionRepository versionRepository;
    private final SecretKeyEnvelopeRepository envelopeRepository;
    private final Clock clock;
    private final SecurityPolicyRepository policyRepository;

    public VaultService(
            SecretRepository secretRepository,
            SecretVersionRepository versionRepository,
            SecretKeyEnvelopeRepository envelopeRepository,
            Clock clock,
            SecurityPolicyRepository policyRepository
    ) {
        this.secretRepository = secretRepository;
        this.versionRepository = versionRepository;
        this.envelopeRepository = envelopeRepository;
        this.clock = clock;
        this.policyRepository = policyRepository;
    }

    @Transactional
    public CreatedSecretResponse create(User owner, CreateSecretRequest request) {
        DecodedSecret decoded = decodeAndValidate(request);

        Secret secret = new Secret(owner);
        scheduleNextRotation(secret);
        secretRepository.save(secret);
        SecretVersion version = versionRepository.save(new SecretVersion(
                secret,
                1,
                decoded.encryptedBlob(),
                decoded.encryptionIv(),
                ENCRYPTION_ALGORITHM,
                owner
        ));
        envelopeRepository.save(new SecretKeyEnvelope(
                version,
                owner,
                decoded.wrappedDataKey(),
                WRAPPING_ALGORITHM,
                owner
        ));

        return new CreatedSecretResponse(secret.getId(), version.getVersionNumber());
    }

    @Transactional(readOnly = true)
    public List<VaultSecretResponse> listOwned(User owner) {
        Base64.Encoder encoder = Base64.getEncoder();
        return secretRepository
                .findAllByOwner_IdAndDeletedAtIsNullOrderByUpdatedAtDesc(owner.getId())
                .stream()
                .map(secret -> toResponse(secret, owner, encoder))
                .toList();
    }

    @Transactional
    public CreatedSecretResponse update(long secretId, User owner, CreateSecretRequest request) {
        DecodedSecret decoded = decodeAndValidate(request);
        Secret secret = findOwnedActiveForUpdate(secretId, owner.getId());
        int nextVersion = secret.getCurrentVersionNumber() + 1;

        SecretVersion version = versionRepository.save(new SecretVersion(
                secret,
                nextVersion,
                decoded.encryptedBlob(),
                decoded.encryptionIv(),
                ENCRYPTION_ALGORITHM,
                owner
        ));
        envelopeRepository.save(new SecretKeyEnvelope(
                version,
                owner,
                decoded.wrappedDataKey(),
                WRAPPING_ALGORITHM,
                owner
        ));
        secret.advanceToVersion(nextVersion);
        scheduleNextRotation(secret);

        return new CreatedSecretResponse(secret.getId(), nextVersion);
    }

    @Transactional
    public void delete(long secretId, User owner) {
        Secret secret = findOwnedActiveForUpdate(secretId, owner.getId());
        secret.softDelete(Instant.now(clock));
    }

    private Secret findOwnedActiveForUpdate(long secretId, long ownerId) {
        return secretRepository.findOwnedActiveForUpdate(secretId, ownerId)
                .orElseThrow(() -> new AuthException(HttpStatus.NOT_FOUND, "Tajna nije pronađena"));
    }

    private VaultSecretResponse toResponse(Secret secret, User owner, Base64.Encoder encoder) {
        SecretVersion version = versionRepository
                .findBySecret_IdAndVersionNumber(secret.getId(), secret.getCurrentVersionNumber())
                .orElseThrow(this::invalidStoredSecret);
        SecretKeyEnvelope envelope = envelopeRepository
                .findBySecretVersion_IdAndRecipient_IdAndRevokedAtIsNull(version.getId(), owner.getId())
                .orElseThrow(this::invalidStoredSecret);

        return new VaultSecretResponse(
                secret.getId(),
                version.getVersionNumber(),
                encoder.encodeToString(version.getEncryptedBlob()),
                encoder.encodeToString(version.getEncryptionIv()),
                version.getEncryptionAlgorithm(),
                encoder.encodeToString(envelope.getWrappedDataKey()),
                envelope.getWrappingAlgorithm(),
                secret.getCreatedAt(),
                secret.getUpdatedAt(),
                secret.getRotationDueAt()
        );
    }

    private void scheduleNextRotation(Secret secret) {
        short days = policyRepository.findFirstByOrderByIdAsc()
                .orElseThrow(() -> new IllegalStateException("Security policy is missing"))
                .getSecretRotationDays();
        secret.scheduleRotation(Instant.now(clock).plusSeconds(days * 86_400L));
    }

    private DecodedSecret decodeAndValidate(CreateSecretRequest request) {
        try {
            byte[] encryptedBlob = Base64.getDecoder().decode(request.encryptedBlobBase64());
            byte[] iv = Base64.getDecoder().decode(request.encryptionIvBase64());
            byte[] wrappedKey = Base64.getDecoder().decode(request.wrappedDataKeyBase64());

            if (encryptedBlob.length < 17 || encryptedBlob.length > MAXIMUM_ENCRYPTED_BLOB_BYTES
                    || iv.length != AES_GCM_IV_BYTES
                    || wrappedKey.length != RSA_3072_CIPHERTEXT_BYTES) {
                throw invalidSubmittedSecret();
            }
            return new DecodedSecret(encryptedBlob, iv, wrappedKey);
        } catch (IllegalArgumentException exception) {
            throw invalidSubmittedSecret();
        }
    }

    private AuthException invalidSubmittedSecret() {
        return new AuthException(HttpStatus.BAD_REQUEST, "Enkriptovana tajna nije ispravna");
    }

    private AuthException invalidStoredSecret() {
        return new AuthException(HttpStatus.INTERNAL_SERVER_ERROR, "Sačuvana tajna nije konzistentna");
    }

    private record DecodedSecret(byte[] encryptedBlob, byte[] encryptionIv, byte[] wrappedDataKey) {
    }
}
