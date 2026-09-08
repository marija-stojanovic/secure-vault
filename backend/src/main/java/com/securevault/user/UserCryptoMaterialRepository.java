package com.securevault.user;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserCryptoMaterialRepository extends JpaRepository<UserCryptoMaterial, Long> {
}
