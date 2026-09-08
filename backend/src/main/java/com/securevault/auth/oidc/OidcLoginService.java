package com.securevault.auth.oidc;

import com.securevault.user.User;
import com.securevault.user.UserRepository;
import com.securevault.user.UserRole;
import com.securevault.user.UserStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OidcLoginService {

    public static final String GOOGLE_ISSUER = "https://accounts.google.com";

    private final OidcIdentityRepository identityRepository;
    private final UserRepository userRepository;

    public OidcLoginService(OidcIdentityRepository identityRepository, UserRepository userRepository) {
        this.identityRepository = identityRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public LoginResult resolveGoogleUser(
            String issuer,
            String subjectIdentifier,
            String email,
            boolean emailVerified
    ) {
        if (!GOOGLE_ISSUER.equals(issuer) || subjectIdentifier == null || subjectIdentifier.isBlank()) {
            throw new OidcLoginException("invalid-provider", "Google identitet nije ispravan");
        }

        User user = identityRepository
                .findByIssuerAndSubjectIdentifier(issuer, subjectIdentifier)
                .map(OidcIdentity::getUser)
                .orElseGet(() -> linkOrCreateVerifiedEmail(issuer, subjectIdentifier, email, emailVerified));

        if (user.getStatus() == UserStatus.PENDING
                && user.getLoginPasswordHash() == null
                && !user.isMfaEnabled()) {
            return new LoginResult(user, true);
        }
        if (user.getStatus() != UserStatus.ACTIVE || !user.isMfaEnabled()) {
            throw new OidcLoginException(
                    "account-inactive",
                    "Lokalni Secure Vault nalog nije aktivan"
            );
        }
        return new LoginResult(user, false);
    }

    private User linkOrCreateVerifiedEmail(
            String issuer,
            String subjectIdentifier,
            String email,
            boolean emailVerified
    ) {
        if (!emailVerified || email == null || email.isBlank()) {
            throw new OidcLoginException("email-unverified", "Google email nije verifikovan");
        }

        String normalizedEmail = email.trim().toLowerCase();
        User user = userRepository.findByEmailIgnoreCase(normalizedEmail)
                .orElseGet(() -> userRepository.save(new User(
                        availableUsername(normalizedEmail),
                        normalizedEmail,
                        null,
                        UserRole.DEVELOPER
                )));

        identityRepository.save(new OidcIdentity(user, issuer, subjectIdentifier));
        return user;
    }

    private String availableUsername(String email) {
        String localPart = email.substring(0, email.indexOf('@'))
                .replaceAll("[^a-zA-Z0-9._-]", "_");
        String base = localPart.isBlank() ? "google-user" : localPart;
        base = base.substring(0, Math.min(base.length(), 90));
        String candidate = base;
        int suffix = 1;
        while (userRepository.existsByUsernameIgnoreCase(candidate)) {
            candidate = base + "-" + suffix++;
        }
        return candidate;
    }

    public record LoginResult(User user, boolean onboardingRequired) {
    }
}
