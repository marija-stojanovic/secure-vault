package com.securevault.auth;

import com.securevault.auth.api.MfaLoginRequest;
import com.securevault.auth.api.PasswordLoginRequest;
import com.securevault.auth.api.PasswordLoginResponse;
import com.securevault.policy.SecurityPolicy;
import com.securevault.policy.SecurityPolicyRepository;
import com.securevault.user.User;
import com.securevault.user.UserRepository;
import com.securevault.user.UserStatus;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.OptionalLong;

@Service
public class LoginService {

    private final UserRepository userRepository;
    private final UserMfaRepository userMfaRepository;
    private final SecurityPolicyRepository policyRepository;
    private final PasswordEncoder passwordEncoder;
    private final MfaChallengeService challengeService;
    private final MfaSecretCryptoService mfaCryptoService;
    private final TotpService totpService;
    private final SessionService sessionService;
    private final Clock clock;
    private final String dummyPasswordHash;

    public LoginService(
            UserRepository userRepository,
            UserMfaRepository userMfaRepository,
            SecurityPolicyRepository policyRepository,
            PasswordEncoder passwordEncoder,
            MfaChallengeService challengeService,
            MfaSecretCryptoService mfaCryptoService,
            TotpService totpService,
            SessionService sessionService,
            Clock clock
    ) {
        this.userRepository = userRepository;
        this.userMfaRepository = userMfaRepository;
        this.policyRepository = policyRepository;
        this.passwordEncoder = passwordEncoder;
        this.challengeService = challengeService;
        this.mfaCryptoService = mfaCryptoService;
        this.totpService = totpService;
        this.sessionService = sessionService;
        this.clock = clock;
        this.dummyPasswordHash = passwordEncoder.encode("not-a-real-user-password");
    }

    @Transactional
    public PasswordLoginResponse verifyPassword(PasswordLoginRequest request) {
        Instant now = Instant.now(clock);
        User user = userRepository.findByUsernameIgnoreCase(request.username().trim()).orElse(null);

        if (user == null) {
            passwordEncoder.matches(request.password(), dummyPasswordHash);
            throw invalidCredentials();
        }
        if (user.getLoginPasswordHash() == null
                || !passwordEncoder.matches(request.password(), user.getLoginPasswordHash())) {
            recordFailedPassword(user, now);
            throw invalidCredentials();
        }
        // Status se otkriva tek nakon ispravne lozinke, da napadač ne bi mogao
        // provjeravati koji nalozi postoje samo pomoću korisničkog imena.
        if (user.getStatus() == UserStatus.FROZEN) {
            throw new AuthException(HttpStatus.FORBIDDEN,
                    "Nalog je zamrznut zbog sigurnosnog događaja. Obrati se administratoru.");
        }
        if (user.getStatus() == UserStatus.DISABLED) {
            throw new AuthException(HttpStatus.FORBIDDEN,
                    "Nalog je trajno deaktiviran i prijava više nije moguća.");
        }
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AuthException(HttpStatus.FORBIDDEN,
                    "Nalog još nije aktiviran. Završi MFA postavljanje.");
        }
        if (user.isLockedAt(now)) {
            throw new AuthException(HttpStatus.LOCKED,
                    "Prijava je privremeno zaključana zbog više pogrešnih pokušaja. Pokušaj kasnije.");
        }
        if (!user.isMfaEnabled()) {
            throw new AuthException(HttpStatus.FORBIDDEN, "MFA nije aktiviran za ovaj nalog");
        }

        MfaChallengeService.IssuedChallenge challenge = challengeService.issue(user.getId());
        return new PasswordLoginResponse(true, challenge.token(), challenge.expiresAt());
    }

    @Transactional
    public CompletedLogin verifyMfa(
            MfaLoginRequest request,
            String ipAddress,
            String userAgent
    ) {
        long userId = challengeService.requireUserId(request.mfaChallenge());
        User user = userRepository.findById(userId).orElseThrow(this::invalidCredentials);
        UserMfa userMfa = userMfaRepository.findById(userId).orElseThrow(this::invalidCredentials);

        if (user.getStatus() != UserStatus.ACTIVE || userMfa.getConfirmedAt() == null) {
            throw invalidCredentials();
        }

        byte[] secret = mfaCryptoService.decrypt(
                userMfa.getEncryptedTotpSecret(),
                userMfa.getEncryptionIv()
        );
        OptionalLong usedStep = totpService.verify(
                secret,
                request.code(),
                userMfa.getLastUsedTimeStep()
        );
        if (usedStep.isEmpty()) {
            challengeService.recordFailure(request.mfaChallenge());
            throw new AuthException(HttpStatus.UNAUTHORIZED, "MFA kod nije ispravan");
        }

        challengeService.consume(request.mfaChallenge());
        userMfa.recordUsedTimeStep(usedStep.getAsLong());
        user.recordSuccessfulLogin(Instant.now(clock));
        SessionService.IssuedSession session = sessionService.create(user, ipAddress, userAgent);
        return new CompletedLogin(user, session);
    }

    private void recordFailedPassword(User user, Instant now) {
        user.recordFailedLoginAttempt();
        SecurityPolicy policy = policyRepository.findFirstByOrderByIdAsc()
                .orElseThrow(() -> new IllegalStateException("Security policy is missing"));
        if (user.getFailedLoginAttempts() >= policy.getMaximumFailedLoginAttempts()) {
            user.lockUntil(now.plusSeconds(policy.getLoginBlockDurationSeconds()));
        }
    }

    private AuthException invalidCredentials() {
        return new AuthException(HttpStatus.UNAUTHORIZED, "Korisničko ime ili lozinka nisu ispravni");
    }

    public record CompletedLogin(User user, SessionService.IssuedSession session) {
    }
}
