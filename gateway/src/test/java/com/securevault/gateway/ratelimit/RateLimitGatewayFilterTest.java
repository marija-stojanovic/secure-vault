package com.securevault.gateway.ratelimit;

import com.securevault.gateway.intrusion.IntrusionProtectionService;
import com.securevault.gateway.intrusion.IpBlock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import jakarta.servlet.http.Cookie;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.util.Optional;
import java.time.Instant;

class RateLimitGatewayFilterTest {

    private RedisRateLimitService service;
    private RateLimitGatewayFilter filter;
    private IntrusionProtectionService intrusionProtection;
    private RateLimitProperties.Rule passwordRule;

    @BeforeEach
    void setUp() {
        service = mock(RedisRateLimitService.class);
        intrusionProtection = mock(IntrusionProtectionService.class);
        when(intrusionProtection.activeBlock(anyString())).thenReturn(Optional.empty());
        when(intrusionProtection.registerRateLimitViolation(anyString())).thenReturn(Optional.empty());
        when(intrusionProtection.registerInvalidToken(anyString(), anyString())).thenReturn(Optional.empty());
        passwordRule = new RateLimitProperties.Rule(5, 60);
        filter = new RateLimitGatewayFilter(service, new RateLimitProperties(
                passwordRule,
                new RateLimitProperties.Rule(10, 300),
                new RateLimitProperties.Rule(5, 3600)
        ), intrusionProtection);
    }

    @Test
    void allowsRequestWhenBucketHasTokens() throws Exception {
        when(service.consume(anyString(), eq(passwordRule)))
                .thenReturn(new RateLimitDecision(true, 4, 0));

        ServerResponse proxiedResponse = ServerResponse.ok().body("backend-response");
        ServerResponse response = filter.filter(passwordRequest(), request -> proxiedResponse);

        assertThat(response).isSameAs(proxiedResponse);
        assertThat(response.statusCode().value()).isEqualTo(200);
    }

    @Test
    void rejectsRequestWhenBucketIsEmpty() throws Exception {
        when(service.consume(anyString(), eq(passwordRule)))
                .thenReturn(new RateLimitDecision(false, 0, 12));

        ServerResponse response = filter.filter(passwordRequest(), request -> ServerResponse.ok().build());

        assertThat(response.statusCode().value()).isEqualTo(429);
        assertThat(response.headers().getFirst("Retry-After")).isEqualTo("12");
    }

    @Test
    void failsClosedWhenRedisIsUnavailable() throws Exception {
        when(service.consume(anyString(), eq(passwordRule))).thenThrow(new IllegalStateException());

        ServerResponse response = filter.filter(passwordRequest(), request -> ServerResponse.ok().build());

        assertThat(response.statusCode().value()).isEqualTo(503);
    }

    @Test
    void ignoresUnprotectedEndpoint() throws Exception {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest("GET", "/api/health");

        ServerResponse response = filter.filter(
                ServerRequest.create(servletRequest, java.util.List.of()),
                request -> ServerResponse.ok().build()
        );

        assertThat(response.statusCode().value()).isEqualTo(200);
        verifyNoInteractions(service);
    }

    @Test
    void rejectsEveryApiRequestFromBlockedIp() throws Exception {
        when(intrusionProtection.activeBlock(anyString())).thenReturn(Optional.of(
                new IpBlock("Sumnjiva aktivnost", Instant.now().plusSeconds(300))));

        ServerResponse response = filter.filter(passwordRequest(), request -> ServerResponse.ok().build());

        assertThat(response.statusCode().value()).isEqualTo(403);
        assertThat(response.headers().getFirst("Retry-After")).isNotBlank();
        verifyNoInteractions(service);
    }

    @Test
    void returns403WhenRateLimitViolationTriggersNewBlock() throws Exception {
        when(service.consume(anyString(), eq(passwordRule)))
                .thenReturn(new RateLimitDecision(false, 0, 12));
        when(intrusionProtection.registerRateLimitViolation(anyString())).thenReturn(Optional.of(
                new IpBlock("Ponavljani prekršaji", Instant.now().plusSeconds(300))));

        ServerResponse response = filter.filter(passwordRequest(), request -> ServerResponse.ok().build());

        assertThat(response.statusCode().value()).isEqualTo(403);
    }

    @Test
    void counts401WithAccessCookieOnProtectedEndpoint() throws Exception {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest("GET", "/api/vault/secrets");
        servletRequest.setRemoteAddr("127.0.0.1");
        servletRequest.setCookies(new Cookie("SV_ACCESS", "expired-token"));

        ServerResponse response = filter.filter(
                ServerRequest.create(servletRequest, java.util.List.of()),
                request -> ServerResponse.status(401).build()
        );

        assertThat(response.statusCode().value()).isEqualTo(401);
        verify(intrusionProtection).registerInvalidToken("127.0.0.1", "expired-token");
    }

    private ServerRequest passwordRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login/password");
        request.setRemoteAddr("127.0.0.1");
        return ServerRequest.create(request, java.util.List.of());
    }
}
