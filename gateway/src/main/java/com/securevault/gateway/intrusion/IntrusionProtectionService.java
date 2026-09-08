package com.securevault.gateway.intrusion;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
@EnableConfigurationProperties(IntrusionProperties.class)
public class IntrusionProtectionService {

    private static final String RATE_LIMIT_REASON = "Ponavljano prekoračenje ograničenja autentikacionih zahtjeva";
    private static final String SUSPICIOUS_INPUT_REASON = "Ponavljani zahtjevi sa sumnjivim sadržajem";
    private static final String INVALID_TOKEN_REASON = "Ponavljano korištenje nevažećeg ili isteklog access tokena";

    private final StringRedisTemplate redis;
    private final JdbcTemplate jdbc;
    private final IntrusionProperties properties;

    public IntrusionProtectionService(
            StringRedisTemplate redis,
            JdbcTemplate jdbc,
            IntrusionProperties properties
    ) {
        this.redis = redis;
        this.jdbc = jdbc;
        this.properties = properties;
    }

    public Optional<IpBlock> activeBlock(String ipAddress) {
        String cachedUntil = redis.opsForValue().get(blockKey(ipAddress));
        if (cachedUntil != null) {
            Instant until = Instant.ofEpochMilli(Long.parseLong(cachedUntil));
            if (until.isAfter(Instant.now())) {
                return jdbc.query(
                        "SELECT reason FROM blocked_ip_addresses WHERE ip_address = ?",
                        result -> result.next()
                                ? Optional.of(new IpBlock(result.getString("reason"), until))
                                : Optional.of(new IpBlock("Sumnjiva aktivnost", until)),
                        ipAddress
                );
            }
            redis.delete(blockKey(ipAddress));
        }

        return jdbc.query(
                """
                SELECT reason, blocked_until
                FROM blocked_ip_addresses
                WHERE ip_address = ? AND blocked_until > UTC_TIMESTAMP(6)
                """,
                result -> {
                    if (!result.next()) return Optional.empty();
                    IpBlock block = new IpBlock(
                            result.getString("reason"),
                            result.getTimestamp("blocked_until").toInstant()
                    );
                    cacheBlock(ipAddress, block.blockedUntil());
                    return Optional.of(block);
                },
                ipAddress
        );
    }

    public Optional<IpBlock> registerRateLimitViolation(String ipAddress) {
        return registerViolation(ipAddress, "rate-limit", properties.violationThreshold(), RATE_LIMIT_REASON);
    }

    public Optional<IpBlock> registerSuspiciousInput(String ipAddress) {
        return registerViolation(ipAddress, "suspicious-input",
                properties.suspiciousInputThreshold(), SUSPICIOUS_INPUT_REASON);
    }

    public Optional<IpBlock> registerInvalidToken(String ipAddress, String rawAccessToken) {
        String duplicateKey = "secure-vault:intrusion:invalid-token-seen:"
                + hash(ipAddress + ":" + rawAccessToken);
        Boolean firstDuringCooldown = redis.opsForValue().setIfAbsent(
                duplicateKey,
                "1",
                properties.invalidTokenCooldownSeconds(),
                TimeUnit.SECONDS
        );
        if (!Boolean.TRUE.equals(firstDuringCooldown)) return Optional.empty();
        return registerViolation(ipAddress, "invalid-token",
                properties.invalidTokenThreshold(), INVALID_TOKEN_REASON);
    }

    private Optional<IpBlock> registerViolation(
            String ipAddress,
            String category,
            long threshold,
            String reason
    ) {
        String key = violationKey(ipAddress, category);
        Long count = redis.opsForValue().increment(key);
        if (count != null && count == 1) {
            redis.expire(key, properties.detectionWindowSeconds(), TimeUnit.SECONDS);
        }
        if (count == null || count < threshold) return Optional.empty();

        Instant now = Instant.now();
        Instant blockedUntil = now.plusSeconds(properties.blockDurationSeconds());
        jdbc.update(
                """
                INSERT INTO blocked_ip_addresses (ip_address, reason, blocked_until, created_at)
                VALUES (?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    reason = VALUES(reason),
                    blocked_until = GREATEST(blocked_until, VALUES(blocked_until)),
                    created_at = VALUES(created_at)
                """,
                ipAddress,
                reason,
                Timestamp.from(blockedUntil),
                Timestamp.from(now)
        );
        redis.delete(key);
        cacheBlock(ipAddress, blockedUntil);
        return Optional.of(new IpBlock(reason, blockedUntil));
    }

    private void cacheBlock(String ipAddress, Instant blockedUntil) {
        Duration duration = Duration.between(Instant.now(), blockedUntil);
        if (!duration.isNegative() && !duration.isZero()) {
            redis.opsForValue().set(blockKey(ipAddress), Long.toString(blockedUntil.toEpochMilli()), duration);
        }
    }

    private String violationKey(String ipAddress, String category) {
        return "secure-vault:intrusion:violations:" + category + ":" + hash(ipAddress);
    }

    public static String blockKey(String ipAddress) {
        return "secure-vault:intrusion:blocked:" + hash(ipAddress);
    }

    private static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 nije dostupan", exception);
        }
    }
}
