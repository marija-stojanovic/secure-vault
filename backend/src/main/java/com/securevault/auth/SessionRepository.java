package com.securevault.auth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;

public interface SessionRepository extends JpaRepository<Session, String> {

    Optional<Session> findByAccessTokenHash(byte[] accessTokenHash);

    Optional<Session> findByRefreshTokenHash(byte[] refreshTokenHash);

    List<Session> findAllByTokenFamilyId(String tokenFamilyId);

    List<Session> findAllByUserId(Long userId);
}
