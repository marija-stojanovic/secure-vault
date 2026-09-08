package com.securevault.security;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

@Service
public class BlockedIpAdminService {

    private final BlockedIpAddressRepository repository;
    private final StringRedisTemplate redis;

    public BlockedIpAdminService(BlockedIpAddressRepository repository, StringRedisTemplate redis) {
        this.repository = repository;
        this.redis = redis;
    }

    @Transactional(readOnly = true)
    public List<BlockedIpResponse> activeBlocks() {
        return repository.findByBlockedUntilAfterOrderByBlockedUntilDesc(Instant.now()).stream()
                .map(BlockedIpResponse::from)
                .toList();
    }

    @Transactional
    public void unblock(String ipAddress) {
        repository.deleteById(ipAddress);
        redis.delete(blockKey(ipAddress));
        redis.delete(violationKey(ipAddress));
    }

    private String blockKey(String ipAddress) {
        return "secure-vault:intrusion:blocked:" + hash(ipAddress);
    }

    private String violationKey(String ipAddress) {
        return "secure-vault:intrusion:violations:" + hash(ipAddress);
    }

    private String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 nije dostupan", exception);
        }
    }

    public record BlockedIpResponse(
            String ipAddress,
            String reason,
            Instant blockedUntil,
            Instant createdAt
    ) {
        static BlockedIpResponse from(BlockedIpAddress block) {
            return new BlockedIpResponse(
                    block.getIpAddress(), block.getReason(), block.getBlockedUntil(), block.getCreatedAt());
        }
    }
}
