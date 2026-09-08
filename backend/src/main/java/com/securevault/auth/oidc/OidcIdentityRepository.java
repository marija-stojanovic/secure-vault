package com.securevault.auth.oidc;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OidcIdentityRepository extends JpaRepository<OidcIdentity, Long> {

    Optional<OidcIdentity> findByIssuerAndSubjectIdentifier(String issuer, String subjectIdentifier);
}
