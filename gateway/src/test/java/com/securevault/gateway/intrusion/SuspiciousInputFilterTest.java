package com.securevault.gateway.intrusion;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SuspiciousInputFilterTest {

    private IntrusionProtectionService intrusionProtection;
    private SuspiciousInputFilter filter;

    @BeforeEach
    void setUp() {
        intrusionProtection = mock(IntrusionProtectionService.class);
        when(intrusionProtection.registerSuspiciousInput(anyString())).thenReturn(Optional.empty());
        filter = new SuspiciousInputFilter(intrusionProtection);
    }

    @Test
    void inspectsBodyWithoutPreventingDownstreamFromReadingIt() throws Exception {
        MockHttpServletRequest request = jsonRequest("{\"username\":\"normal-user\"}");
        MockHttpServletResponse response = new MockHttpServletResponse();
        StringBuilder downstreamBody = new StringBuilder();
        FilterChain chain = (wrappedRequest, ignored) -> downstreamBody.append(
                new String(wrappedRequest.getInputStream().readAllBytes(), StandardCharsets.UTF_8));

        filter.doFilter(request, response, chain);

        assertThat(downstreamBody).hasToString("{\"username\":\"normal-user\"}");
    }

    @Test
    void recordsSuspiciousSqlInput() throws Exception {
        MockHttpServletRequest request = jsonRequest("{\"username\":\"' OR 1=1 --\"}");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mock(FilterChain.class));

        verify(intrusionProtection).registerSuspiciousInput("127.0.0.1");
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getContentAsString()).contains("SUSPICIOUS_INPUT");
    }

    @Test
    void blocksRequestWhenSuspiciousThresholdIsReached() throws Exception {
        MockHttpServletRequest request = jsonRequest("{\"value\":\"UNION SELECT password\"}");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(intrusionProtection.registerSuspiciousInput(anyString())).thenReturn(Optional.of(
                new IpBlock("Ponavljani zahtjevi sa sumnjivim sadržajem", Instant.now().plusSeconds(300))));

        filter.doFilter(request, response, mock(FilterChain.class));

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("IP_BLOCKED");
    }

    private MockHttpServletRequest jsonRequest(String body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login/password");
        request.setRemoteAddr("127.0.0.1");
        request.setContentType("application/json");
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        return request;
    }
}
