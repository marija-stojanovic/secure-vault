package com.securevault.sharing;

import com.securevault.auth.AuthException;
import com.securevault.sharing.api.ReceivedSecretResponse;
import com.securevault.sharing.api.ShareRecipientResponse;
import com.securevault.sharing.api.ShareSecretRequest;
import com.securevault.sharing.api.SharedRecipientResponse;
import com.securevault.user.User;
import com.securevault.user.UserCryptoMaterial;
import com.securevault.user.UserCryptoMaterialRepository;
import com.securevault.user.UserRepository;
import com.securevault.user.UserRole;
import com.securevault.user.UserStatus;
import com.securevault.vault.Secret;
import com.securevault.vault.SecretKeyEnvelope;
import com.securevault.vault.SecretKeyEnvelopeRepository;
import com.securevault.vault.SecretRepository;
import com.securevault.vault.SecretVersion;
import com.securevault.vault.SecretVersionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

@Service
public class SharingService {

    private static final int RSA_3072_CIPHERTEXT_BYTES = 384;
    private static final String WRAPPING_ALGORITHM = "RSA-OAEP-3072";

    private final UserRepository userRepository;
    private final UserCryptoMaterialRepository cryptoMaterialRepository;
    private final SecretRepository secretRepository;
    private final SecretVersionRepository versionRepository;
    private final SecretKeyEnvelopeRepository envelopeRepository;
    private final Clock clock;

    public SharingService(
            UserRepository userRepository,
            UserCryptoMaterialRepository cryptoMaterialRepository,
            SecretRepository secretRepository,
            SecretVersionRepository versionRepository,
            SecretKeyEnvelopeRepository envelopeRepository,
            Clock clock
    ) {
        this.userRepository = userRepository;
        this.cryptoMaterialRepository = cryptoMaterialRepository;
        this.secretRepository = secretRepository;
        this.versionRepository = versionRepository;
        this.envelopeRepository = envelopeRepository;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<ShareRecipientResponse> listDevelopers(User teamLead) {
        requireRole(teamLead, UserRole.TEAM_LEAD);
        Base64.Encoder encoder = Base64.getEncoder();
        return userRepository.findAllByRoleAndStatusOrderByUsernameAsc(UserRole.DEVELOPER, UserStatus.ACTIVE)
                .stream()
                .map(user -> {
                    UserCryptoMaterial material = cryptoMaterialRepository.findById(user.getId())
                            .orElseThrow(this::inconsistentCryptoMaterial);
                    return new ShareRecipientResponse(
                            user.getId(),
                            user.getUsername(),
                            user.getEmail(),
                            material.getPublicKeyAlgorithm(),
                            encoder.encodeToString(material.getPublicKeySpki())
                    );
                })
                .toList();
    }

    @Transactional
    public void share(long secretId, User teamLead, ShareSecretRequest request) {
        requireRole(teamLead, UserRole.TEAM_LEAD);
        Secret secret = findOwnedActiveForUpdate(secretId, teamLead.getId());
        if (secret.getRotationDueAt() == null || !secret.getRotationDueAt().isAfter(Instant.now(clock))) {
            throw new AuthException(HttpStatus.CONFLICT, "Tajna mora biti rotirana prije dijeljenja");
        }
        if (secret.getCurrentVersionNumber() != request.versionNumber()) {
            throw new AuthException(HttpStatus.CONFLICT, "Tajna je u međuvremenu dobila novu verziju");
        }

        User recipient = userRepository.findById(request.recipientUserId())
                .filter(user -> user.getRole() == UserRole.DEVELOPER)
                .filter(user -> user.getStatus() == UserStatus.ACTIVE)
                .orElseThrow(() -> new AuthException(HttpStatus.BAD_REQUEST, "Primalac mora biti aktivan Developer"));
        byte[] wrappedDataKey = decodeWrappedKey(request.wrappedDataKeyBase64());
        SecretVersion version = currentVersion(secret);

        envelopeRepository.findBySecretVersion_IdAndRecipient_Id(version.getId(), recipient.getId())
                .ifPresentOrElse(
                        envelope -> envelope.replaceAndReactivate(wrappedDataKey, teamLead),
                        () -> envelopeRepository.save(new SecretKeyEnvelope(
                                version,
                                recipient,
                                wrappedDataKey,
                                WRAPPING_ALGORITHM,
                                teamLead
                        ))
                );
    }

    @Transactional(readOnly = true)
    public List<SharedRecipientResponse> listRecipients(long secretId, User teamLead) {
        requireRole(teamLead, UserRole.TEAM_LEAD);
        Secret secret = secretRepository.findByIdAndOwner_IdAndDeletedAtIsNull(secretId, teamLead.getId())
                .orElseThrow(this::secretNotFound);
        SecretVersion version = currentVersion(secret);
        return envelopeRepository.findAllBySecretVersion_Id(version.getId())
                .stream()
                .filter(envelope -> envelope.getRevokedAt() == null)
                .map(SecretKeyEnvelope::getRecipient)
                .filter(recipient -> recipient.getRole() == UserRole.DEVELOPER)
                .map(recipient -> new SharedRecipientResponse(
                        recipient.getId(), recipient.getUsername(), recipient.getEmail()
                ))
                .toList();
    }

    @Transactional
    public void revoke(long secretId, long recipientId, User teamLead) {
        requireRole(teamLead, UserRole.TEAM_LEAD);
        Secret secret = findOwnedActiveForUpdate(secretId, teamLead.getId());
        SecretVersion version = currentVersion(secret);
        SecretKeyEnvelope envelope = envelopeRepository
                .findBySecretVersion_IdAndRecipient_IdAndRevokedAtIsNull(version.getId(), recipientId)
                .orElseThrow(() -> new AuthException(HttpStatus.NOT_FOUND, "Aktivno dijeljenje nije pronađeno"));
        envelope.revoke(Instant.now(clock));
    }

    @Transactional(readOnly = true)
    public List<ReceivedSecretResponse> listReceived(User developer) {
        requireRole(developer, UserRole.DEVELOPER);
        Base64.Encoder encoder = Base64.getEncoder();
        return envelopeRepository.findAllByRecipient_IdAndRevokedAtIsNull(developer.getId())
                .stream()
                .filter(envelope -> isCurrentActiveShare(envelope, developer.getId()))
                .map(envelope -> toReceivedResponse(envelope, encoder))
                .toList();
    }

    private boolean isCurrentActiveShare(SecretKeyEnvelope envelope, long recipientId) {
        SecretVersion version = envelope.getSecretVersion();
        Secret secret = version.getSecret();
        return secret.getDeletedAt() == null
                && secret.getOwner().getId() != recipientId
                && secret.getCurrentVersionNumber() == version.getVersionNumber()
                && secret.getRotationDueAt() != null
                && secret.getRotationDueAt().isAfter(Instant.now(clock));
    }

    private ReceivedSecretResponse toReceivedResponse(
            SecretKeyEnvelope envelope,
            Base64.Encoder encoder
    ) {
        SecretVersion version = envelope.getSecretVersion();
        Secret secret = version.getSecret();
        return new ReceivedSecretResponse(
                secret.getId(),
                secret.getOwner().getId(),
                secret.getOwner().getUsername(),
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

    private SecretVersion currentVersion(Secret secret) {
        return versionRepository.findBySecret_IdAndVersionNumber(
                        secret.getId(), secret.getCurrentVersionNumber())
                .orElseThrow(() -> new AuthException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "Trenutna verzija tajne nije pronađena"
                ));
    }

    private Secret findOwnedActiveForUpdate(long secretId, long ownerId) {
        return secretRepository.findOwnedActiveForUpdate(secretId, ownerId)
                .orElseThrow(this::secretNotFound);
    }

    private byte[] decodeWrappedKey(String encoded) {
        try {
            byte[] decoded = Base64.getDecoder().decode(encoded);
            if (decoded.length != RSA_3072_CIPHERTEXT_BYTES) {
                throw new IllegalArgumentException("invalid length");
            }
            return decoded;
        } catch (IllegalArgumentException exception) {
            throw new AuthException(HttpStatus.BAD_REQUEST, "Enkriptovani ključ tajne nije ispravan");
        }
    }

    private void requireRole(User user, UserRole role) {
        if (user.getRole() != role) {
            throw new AuthException(HttpStatus.FORBIDDEN, "Korisnik nema dozvolu za ovu operaciju");
        }
    }

    private AuthException secretNotFound() {
        return new AuthException(HttpStatus.NOT_FOUND, "Tajna nije pronađena");
    }

    private AuthException inconsistentCryptoMaterial() {
        return new AuthException(HttpStatus.INTERNAL_SERVER_ERROR, "Javni ključ korisnika nije pronađen");
    }
}
