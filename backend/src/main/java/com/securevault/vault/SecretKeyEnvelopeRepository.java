package com.securevault.vault;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;

public interface SecretKeyEnvelopeRepository extends JpaRepository<SecretKeyEnvelope, Long> {
    Optional<SecretKeyEnvelope> findBySecretVersion_IdAndRecipient_IdAndRevokedAtIsNull(
            Long secretVersionId,
            Long recipientId
    );

    Optional<SecretKeyEnvelope> findBySecretVersion_IdAndRecipient_Id(
            Long secretVersionId,
            Long recipientId
    );

    List<SecretKeyEnvelope> findAllBySecretVersion_Id(Long secretVersionId);

    List<SecretKeyEnvelope> findAllByRecipient_IdAndRevokedAtIsNull(Long recipientId);
}
