package com.securevault.gateway.ratelimit;

import com.securevault.gateway.intrusion.IntrusionProtectionService;
import com.securevault.gateway.intrusion.IpBlock;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.function.HandlerFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;

@Component
public class RateLimitGatewayFilter {

    private final RedisRateLimitService limiter;
    private final RateLimitProperties properties;
    private final IntrusionProtectionService intrusionProtection;

    public RateLimitGatewayFilter(
            RedisRateLimitService limiter,
            RateLimitProperties properties,
            IntrusionProtectionService intrusionProtection
    ) {
        this.limiter = limiter;
        this.properties = properties;
        this.intrusionProtection = intrusionProtection;
    }

    public ServerResponse filter(ServerRequest request, HandlerFunction<ServerResponse> next)
            throws Exception {
        String clientIp = request.servletRequest().getRemoteAddr();
        boolean recoveryEndpoint = request.path().startsWith("/api/admin/blocked-ips")
                || request.path().equals("/api/auth/csrf");
        if (!recoveryEndpoint) {
            try {
                Optional<IpBlock> activeBlock = intrusionProtection.activeBlock(clientIp);
                if (activeBlock.isPresent()) return blockedResponse(activeBlock.get());
            } catch (RuntimeException exception) {
                return jsonError(503, "INTRUSION_PROTECTION_UNAVAILABLE",
                        "Servis za provjeru IP adrese trenutno nije dostupan.");
            }
        }

        RateLimitRule selected = selectRule(request);
        if (selected != null) {
            RateLimitDecision decision;
            try {
                String key = "secure-vault:rate-limit:" + selected.name() + ":" + hash(clientIp);
                decision = limiter.consume(key, selected.rule());
            } catch (RuntimeException exception) {
                return jsonError(503, "RATE_LIMIT_UNAVAILABLE",
                        "Servis za zaštitu prijave trenutno nije dostupan.");
            }

            if (!decision.allowed()) {
                Optional<IpBlock> newBlock;
                try {
                    newBlock = intrusionProtection.registerRateLimitViolation(clientIp);
                } catch (RuntimeException exception) {
                    return jsonError(503, "INTRUSION_PROTECTION_UNAVAILABLE",
                            "Servis za evidentiranje sigurnosnog događaja trenutno nije dostupan.");
                }
                if (newBlock.isPresent()) return blockedResponse(newBlock.get());

                return ServerResponse.status(429)
                        .header("X-RateLimit-Limit", Long.toString(selected.rule().capacity()))
                        .header("X-RateLimit-Remaining", Long.toString(decision.remaining()))
                        .header("Retry-After", Long.toString(Math.max(1, decision.retryAfterSeconds())))
                        .body(Map.of(
                                "code", "RATE_LIMIT_EXCEEDED",
                                "error", "Previše pokušaja. Pokušaj ponovo nakon isteka ograničenja."
                        ));
            }
        }

        // The response returned by Spring Cloud Gateway MVC can contain a
        // streaming/proxied body. Rebuilding it with ServerResponse.from(...)
        // copies the headers (including Content-Length), but does not safely
        // preserve that body. The browser would consequently receive 200 OK
        // and wait indefinitely for the advertised bytes. Return the original
        // proxy response unchanged; rate-limit headers are still included on
        // the locally-created 429 response below.
        ServerResponse response = next.handle(request);
        Optional<String> rejectedAccessToken = rejectedAccessToken(request, response);
        if (rejectedAccessToken.isPresent()) {
            try {
                Optional<IpBlock> newBlock = intrusionProtection.registerInvalidToken(
                        clientIp, rejectedAccessToken.get());
                if (newBlock.isPresent()) return blockedResponse(newBlock.get());
            } catch (RuntimeException exception) {
                return jsonError(503, "INTRUSION_PROTECTION_UNAVAILABLE",
                        "Servis za evidentiranje sigurnosnog događaja trenutno nije dostupan.");
            }
        }
        return response;
    }

    private Optional<String> rejectedAccessToken(ServerRequest request, ServerResponse response) {
        if (response.statusCode().value() != 401 || !request.path().startsWith("/api/")
                || isPublicAuthenticationPath(request.path())) {
            return Optional.empty();
        }
        return request.cookies().getOrDefault("SV_ACCESS", java.util.List.of()).stream()
                .map(cookie -> cookie.getValue())
                .filter(value -> value != null && !value.isBlank())
                .findFirst();
    }

    private boolean isPublicAuthenticationPath(String path) {
        return path.equals("/api/auth/login/password")
                || path.equals("/api/auth/login/mfa")
                || path.equals("/api/auth/register")
                || path.equals("/api/auth/refresh")
                || path.equals("/api/auth/logout")
                || path.equals("/api/auth/csrf")
                || path.equals("/api/auth/oidc/setup")
                || path.equals("/api/auth/oidc/mfa")
                || path.equals("/api/auth/mfa/confirm");
    }

    private RateLimitRule selectRule(ServerRequest request) {
        if (!"POST".equalsIgnoreCase(request.method().name())) return null;
        return switch (request.path()) {
            case "/api/auth/login/password" -> new RateLimitRule("password", properties.password());
            case "/api/auth/login/mfa", "/api/auth/oidc/mfa", "/api/auth/mfa/confirm" ->
                    new RateLimitRule("mfa", properties.mfa());
            case "/api/auth/register", "/api/auth/oidc/setup" ->
                    new RateLimitRule("registration", properties.registration());
            default -> null;
        };
    }

    private String hash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 nije dostupan", exception);
        }
    }

    private ServerResponse jsonError(int status, String code, String error) {
        return ServerResponse.status(status).body(Map.of("code", code, "error", error));
    }

    private ServerResponse blockedResponse(IpBlock block) {
        long retryAfter = Math.max(1, java.time.Duration.between(
                java.time.Instant.now(), block.blockedUntil()).toSeconds());
        return ServerResponse.status(403)
                .header("Retry-After", Long.toString(retryAfter))
                .body(Map.of(
                        "code", "IP_BLOCKED",
                        "error", "IP adresa je privremeno blokirana zbog sumnjive aktivnosti.",
                        "reason", block.reason(),
                        "blockedUntil", block.blockedUntil().toString()
                ));
    }

    private record RateLimitRule(String name, RateLimitProperties.Rule rule) {
    }
}
