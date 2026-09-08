package com.securevault.gateway.ratelimit;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.rate-limit")
public record RateLimitProperties(Rule password, Rule mfa, Rule registration) {

    public RateLimitProperties {
        validate("password", password);
        validate("mfa", mfa);
        validate("registration", registration);
    }

    private static void validate(String name, Rule rule) {
        if (rule == null || rule.capacity() < 1 || rule.refillSeconds() < 1) {
            throw new IllegalArgumentException("Rate limit '" + name + "' mora imati pozitivne vrijednosti");
        }
    }

    public record Rule(long capacity, long refillSeconds) {
    }
}
