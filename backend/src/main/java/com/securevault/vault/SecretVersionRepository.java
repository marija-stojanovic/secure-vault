package com.securevault.vault;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SecretVersionRepository extends JpaRepository<SecretVersion, Long> {
    Optional<SecretVersion> findBySecret_IdAndVersionNumber(Long secretId, int versionNumber);
}
