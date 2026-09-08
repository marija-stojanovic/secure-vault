package com.securevault.policy;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SecurityPolicyRepository extends JpaRepository<SecurityPolicy, Long> {

    Optional<SecurityPolicy> findFirstByOrderByIdAsc();
}
