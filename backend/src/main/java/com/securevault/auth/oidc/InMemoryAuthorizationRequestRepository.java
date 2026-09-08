package com.securevault.auth.oidc;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryAuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final Duration LIFETIME = Duration.ofMinutes(5);

    private final ConcurrentHashMap<String, StoredRequest> requests = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryAuthorizationRequestRepository(Clock clock) {
        this.clock = clock;
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        String state = request.getParameter("state");
        if (state == null || state.isBlank()) {
            return null;
        }
        StoredRequest stored = requests.get(state);
        if (stored == null || !stored.expiresAt().isAfter(Instant.now(clock))) {
            requests.remove(state);
            return null;
        }
        return stored.request();
    }

    @Override
    public void saveAuthorizationRequest(
            OAuth2AuthorizationRequest authorizationRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        removeExpired();
        if (authorizationRequest == null) {
            String state = request.getParameter("state");
            if (state != null) {
                requests.remove(state);
            }
            return;
        }
        requests.put(
                authorizationRequest.getState(),
                new StoredRequest(authorizationRequest, Instant.now(clock).plus(LIFETIME))
        );
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String state = request.getParameter("state");
        if (state == null || state.isBlank()) {
            return null;
        }
        StoredRequest stored = requests.remove(state);
        if (stored == null || !stored.expiresAt().isAfter(Instant.now(clock))) {
            return null;
        }
        return stored.request();
    }

    private void removeExpired() {
        Instant now = Instant.now(clock);
        requests.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
    }

    private record StoredRequest(OAuth2AuthorizationRequest request, Instant expiresAt) {
    }
}
