package com.securevault.honeypot;

import com.securevault.auth.AuthException;
import com.securevault.auth.SessionService;
import com.securevault.security.SecurityAlert;
import com.securevault.security.SecurityAlertRepository;
import com.securevault.security.SecurityAlertSeverity;
import com.securevault.user.User;
import com.securevault.user.UserRepository;
import com.securevault.user.UserStatus;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class HoneypotService {

    private static final int CONTROL_ID = 1;
    private final HoneypotControlRepository controlRepository;
    private final SecurityAlertRepository alertRepository;
    private final UserRepository userRepository;
    private final SessionService sessionService;
    private final IsolatedHoneypotQueryExecutor queryExecutor;
    private final Clock clock;

    public HoneypotService(HoneypotControlRepository controlRepository,
                            SecurityAlertRepository alertRepository,
                            UserRepository userRepository,
                            SessionService sessionService,
                            IsolatedHoneypotQueryExecutor queryExecutor,
                            Clock clock) {
        this.controlRepository = controlRepository;
        this.alertRepository = alertRepository;
        this.userRepository = userRepository;
        this.sessionService = sessionService;
        this.queryExecutor = queryExecutor;
        this.clock = clock;
    }

    @Transactional
    public HoneypotStatus status() {
        HoneypotControl control = control();
        Instant now = Instant.now(clock);
        if (!control.isEnabledAt(now) && control.getEnabledUntil() != null) {
            control.disable();
        }
        return HoneypotStatus.from(control, now);
    }

    @Transactional
    public HoneypotStatus configure(boolean enabled, int durationMinutes, User administrator) {
        HoneypotControl control = control();
        if (enabled) {
            if (durationMinutes < 1 || durationMinutes > 15) {
                throw new AuthException(HttpStatus.BAD_REQUEST,
                        "Demo endpoint može biti uključen između 1 i 15 minuta");
            }
            control.enableUntil(Instant.now(clock).plus(durationMinutes, ChronoUnit.MINUTES), administrator.getId());
        } else {
            control.disable();
        }
        return HoneypotStatus.from(control, Instant.now(clock));
    }

    @Transactional
    public DemoSearchResult executeIsolatedDemoSearch(String query, User actor, String ipAddress) {
        HoneypotControl control = control();
        if (!control.isEnabledAt(Instant.now(clock))) {
            if (control.getEnabledUntil() != null) control.disable();
            throw new AuthException(HttpStatus.NOT_FOUND, "Demo endpoint nije aktivan");
        }

        int matchCount;
        try {
            matchCount = queryExecutor.unsafeSearch(query);
        } catch (IsolatedHoneypotQueryExecutor.HoneypotQueryException exception) {
            if (exception.getDatabaseErrorCode() == 1045) {
                throw new AuthException(HttpStatus.SERVICE_UNAVAILABLE,
                        "Izolovani demo MySQL nalog nije podešen ili prijava nije uspjela");
            }
            throw new AuthException(HttpStatus.BAD_REQUEST,
                    "Demo SQL upit nije ispravan ili nije dozvoljen izolovanom MySQL nalogu");
        }

        if (matchCount == 0) return new DemoSearchResult(false, 0);

        User managedActor = userRepository.findById(actor.getId())
                .orElseThrow(() -> new AuthException(HttpStatus.UNAUTHORIZED, "Korisnik nije pronađen"));
        if (managedActor.getStatus() == UserStatus.ACTIVE) {
            managedActor.changeStatus(UserStatus.FROZEN);
            sessionService.revokeAllForUser(managedActor.getId());
        }
        alertRepository.save(new SecurityAlert(
                managedActor,
                "HONEYTOKEN_ACCESSED",
                SecurityAlertSeverity.CRITICAL,
                ipAddress,
                "Detektovan je pokušaj pristupa izolovanom honeytoken zapisu; nalog je automatski zamrznut."
        ));
        return new DemoSearchResult(true, matchCount);
    }

    private HoneypotControl control() {
        return controlRepository.findById(CONTROL_ID)
                .orElseGet(() -> controlRepository.save(new HoneypotControl(CONTROL_ID)));
    }

    public record HoneypotStatus(boolean enabled, Instant enabledUntil, Long enabledBy) {
        static HoneypotStatus from(HoneypotControl control, Instant now) {
            return new HoneypotStatus(control.isEnabledAt(now), control.getEnabledUntil(), control.getEnabledBy());
        }
    }

    public record DemoSearchResult(boolean triggered, int matchCount) { }
}
