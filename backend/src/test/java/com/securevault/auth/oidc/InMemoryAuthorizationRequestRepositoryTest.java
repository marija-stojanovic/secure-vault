package com.securevault.auth.oidc;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class InMemoryAuthorizationRequestRepositoryTest {

    @Test
    void storesAndConsumesRequestByUnpredictableState() {
        InMemoryAuthorizationRequestRepository repository = new InMemoryAuthorizationRequestRepository(
                Clock.fixed(Instant.parse("2026-08-26T12:00:00Z"), ZoneOffset.UTC)
        );
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .clientId("test-client")
                .redirectUri("http://localhost:8080/login/oauth2/code/google")
                .state("random-state")
                .build();
        MockHttpServletRequest initialRequest = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        repository.saveAuthorizationRequest(authorizationRequest, initialRequest, response);

        MockHttpServletRequest callback = new MockHttpServletRequest();
        callback.setParameter("state", "random-state");
        assertNotNull(repository.loadAuthorizationRequest(callback));
        assertNotNull(repository.removeAuthorizationRequest(callback, response));
        assertNull(repository.loadAuthorizationRequest(callback));
    }
}
