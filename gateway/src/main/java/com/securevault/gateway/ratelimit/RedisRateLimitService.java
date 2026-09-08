package com.securevault.gateway.ratelimit;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RedisRateLimitService {

    private static final DefaultRedisScript<List> TOKEN_BUCKET_SCRIPT = new DefaultRedisScript<>("""
            local capacity = tonumber(ARGV[1])
            local refill_period_ms = tonumber(ARGV[2])
            local requested = tonumber(ARGV[3])
            local redis_time = redis.call('TIME')
            local now_ms = redis_time[1] * 1000 + math.floor(redis_time[2] / 1000)
            local bucket = redis.call('HMGET', KEYS[1], 'tokens', 'updated_at')
            local tokens = tonumber(bucket[1])
            local updated_at = tonumber(bucket[2])

            if tokens == nil then tokens = capacity end
            if updated_at == nil then updated_at = now_ms end

            local elapsed = math.max(0, now_ms - updated_at)
            local refill_per_ms = capacity / refill_period_ms
            tokens = math.min(capacity, tokens + elapsed * refill_per_ms)

            local allowed = 0
            if tokens >= requested then
                tokens = tokens - requested
                allowed = 1
            end

            local retry_after = 0
            if allowed == 0 then
                retry_after = math.ceil((requested - tokens) / refill_per_ms / 1000)
            end

            redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'updated_at', tostring(now_ms))
            redis.call('PEXPIRE', KEYS[1], math.ceil(refill_period_ms * 2))
            return {allowed, math.floor(tokens), retry_after}
            """, List.class);

    private final StringRedisTemplate redis;

    public RedisRateLimitService(StringRedisTemplate redis) {
        this.redis = redis;
    }

    public RateLimitDecision consume(String key, RateLimitProperties.Rule rule) {
        List<?> result = redis.execute(
                TOKEN_BUCKET_SCRIPT,
                List.of(key),
                Long.toString(rule.capacity()),
                Long.toString(rule.refillSeconds() * 1000),
                "1"
        );
        if (result == null || result.size() != 3) {
            throw new IllegalStateException("Redis nije vratio ispravnu rate-limit odluku");
        }
        return new RateLimitDecision(
                number(result.get(0)) == 1,
                number(result.get(1)),
                number(result.get(2))
        );
    }

    private long number(Object value) {
        if (value instanceof Number number) return number.longValue();
        return Long.parseLong(value.toString());
    }
}
