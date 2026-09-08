package com.securevault.security;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface BlockedIpAddressRepository extends JpaRepository<BlockedIpAddress, String> {
    List<BlockedIpAddress> findByBlockedUntilAfterOrderByBlockedUntilDesc(Instant now);
}
