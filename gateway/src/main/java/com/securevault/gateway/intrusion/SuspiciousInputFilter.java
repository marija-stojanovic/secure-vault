package com.securevault.gateway.intrusion;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class SuspiciousInputFilter extends OncePerRequestFilter {

    private static final int MAX_INSPECTED_BODY_BYTES = 65_536;
    private static final Pattern SUSPICIOUS = Pattern.compile(
            "(?is)(<\\s*script\\b|javascript\\s*:|\\$\\{\\s*jndi\\s*:|"
                    + "(?:union\\s+(?:all\\s+)?select\\b)|(?:information_schema\\b)|"
                    + "(?:\\bor\\b\\s+['\"0-9]+\\s*=\\s*['\"0-9]+)|"
                    + "(?:sleep|benchmark)\\s*\\(|(?:\\.\\./){2,})"
    );

    private final IntrusionProtectionService intrusionProtection;

    public SuspiciousInputFilter(IntrusionProtectionService intrusionProtection) {
        this.intrusionProtection = intrusionProtection;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/")
                // Namjerno ranjiv, vremenski ograničen i na backendu izolovan demo endpoint.
                || request.getRequestURI().equals("/api/demo/honeypot/search")
                || "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        RepeatableBodyRequest wrapped = wrap(request, response);
        if (wrapped == null) return;

        String inspected = String.join("\n",
                request.getRequestURI(),
                Optional.ofNullable(request.getQueryString()).orElse(""),
                wrapped.bodyAsText()
        ).toLowerCase(Locale.ROOT);

        if (SUSPICIOUS.matcher(inspected).find()) {
            try {
                Optional<IpBlock> block = intrusionProtection.registerSuspiciousInput(request.getRemoteAddr());
                if (block.isPresent()) {
                    writeBlocked(response, block.get());
                    return;
                }
                writeJson(response, 400,
                        "{\"code\":\"SUSPICIOUS_INPUT\","
                                + "\"error\":\"Zahtjev sadrži nedozvoljen obrazac.\"}");
                return;
            } catch (RuntimeException exception) {
                writeJson(response, 503,
                        "{\"code\":\"INTRUSION_PROTECTION_UNAVAILABLE\","
                                + "\"error\":\"Servis za sigurnosnu provjeru trenutno nije dostupan.\"}");
                return;
            }
        }

        filterChain.doFilter(wrapped, response);
    }

    private RepeatableBodyRequest wrap(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        byte[] body = request.getInputStream().readNBytes(MAX_INSPECTED_BODY_BYTES + 1);
        if (body.length > MAX_INSPECTED_BODY_BYTES) {
            writeJson(response, 413,
                    "{\"code\":\"REQUEST_TOO_LARGE\","
                            + "\"error\":\"Zahtjev je prevelik.\"}");
            return null;
        }
        return new RepeatableBodyRequest(request, body);
    }

    private void writeBlocked(HttpServletResponse response, IpBlock block) throws IOException {
        long retryAfter = Math.max(1, Duration.between(Instant.now(), block.blockedUntil()).toSeconds());
        response.setHeader("Retry-After", Long.toString(retryAfter));
        writeJson(response, 403,
                "{\"code\":\"IP_BLOCKED\","
                        + "\"error\":\"IP adresa je privremeno blokirana zbog sumnjive aktivnosti.\","
                        + "\"reason\":\"Ponavljani zahtjevi sa sumnjivim sadržajem\","
                        + "\"blockedUntil\":\"" + block.blockedUntil() + "\"}");
    }

    private void writeJson(HttpServletResponse response, int status, String json) throws IOException {
        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        response.getWriter().write(json);
    }
}
