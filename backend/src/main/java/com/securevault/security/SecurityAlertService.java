package com.securevault.security;

import com.securevault.auth.AuthException;
import com.securevault.security.api.SecurityAlertResponse;
import com.securevault.user.User;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

@Service
public class SecurityAlertService {

    private final SecurityAlertRepository repository;
    private final Clock clock;

    public SecurityAlertService(SecurityAlertRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<SecurityAlertResponse> list() {
        return repository.findAllByOrderByCreatedAtDesc().stream()
                .map(SecurityAlertResponse::from)
                .toList();
    }

    @Transactional
    public SecurityAlertResponse acknowledge(long alertId, User administrator) {
        SecurityAlert alert = repository.findById(alertId)
                .orElseThrow(() -> new AuthException(HttpStatus.NOT_FOUND, "Upozorenje nije pronađeno"));
        alert.acknowledge(administrator, Instant.now(clock));
        return SecurityAlertResponse.from(alert);
    }
}
