package com.securevault.vault;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;

public interface SecretRepository extends JpaRepository<Secret, Long> {
    List<Secret> findAllByOwner_IdAndDeletedAtIsNullOrderByUpdatedAtDesc(Long ownerId);

    List<Secret> findAllByDeletedAtIsNull();

    Optional<Secret> findByIdAndOwner_IdAndDeletedAtIsNull(Long secretId, Long ownerId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select secret from Secret secret
            where secret.id = :secretId
              and secret.owner.id = :ownerId
              and secret.deletedAt is null
            """)
    Optional<Secret> findOwnedActiveForUpdate(
            @Param("secretId") Long secretId,
            @Param("ownerId") Long ownerId
    );
}
