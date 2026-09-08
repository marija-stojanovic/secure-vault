package com.securevault.auth.oidc;

import com.securevault.user.User;
import com.securevault.user.UserRepository;
import com.securevault.user.UserRole;
import com.securevault.user.UserStatus;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OidcLoginServiceTest {

    private final OidcIdentityRepository identityRepository = mock(OidcIdentityRepository.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final OidcLoginService service = new OidcLoginService(identityRepository, userRepository);

    @Test
    void linksVerifiedGoogleEmailToExistingActiveMfaUser() {
        User user = activeMfaUser("developer@gmail.com");
        when(identityRepository.findByIssuerAndSubjectIdentifier(
                OidcLoginService.GOOGLE_ISSUER,
                "google-subject"
        )).thenReturn(Optional.empty());
        when(userRepository.findByEmailIgnoreCase("developer@gmail.com"))
                .thenReturn(Optional.of(user));

        OidcLoginService.LoginResult resolved = service.resolveGoogleUser(
                OidcLoginService.GOOGLE_ISSUER,
                "google-subject",
                "developer@gmail.com",
                true
        );

        assertSame(user, resolved.user());
        assertEquals(false, resolved.onboardingRequired());
        verify(identityRepository).save(any(OidcIdentity.class));
    }

    @Test
    void automaticallyRegistersUnknownVerifiedGoogleAccount() {
        when(identityRepository.findByIssuerAndSubjectIdentifier(
                OidcLoginService.GOOGLE_ISSUER,
                "google-subject"
        )).thenReturn(Optional.empty());
        when(userRepository.findByEmailIgnoreCase("unknown@gmail.com"))
                .thenReturn(Optional.empty());
        when(userRepository.existsByUsernameIgnoreCase("unknown")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        OidcLoginService.LoginResult result = service.resolveGoogleUser(
                OidcLoginService.GOOGLE_ISSUER,
                "google-subject",
                "unknown@gmail.com",
                true
        );

        assertEquals("unknown", result.user().getUsername());
        assertEquals("unknown@gmail.com", result.user().getEmail());
        assertEquals(UserRole.DEVELOPER, result.user().getRole());
        assertEquals(UserStatus.PENDING, result.user().getStatus());
        assertTrue(result.onboardingRequired());
        verify(userRepository).save(any(User.class));
        verify(identityRepository).save(any(OidcIdentity.class));
    }

    @Test
    void rejectsUnverifiedEmailBeforeLinking() {
        when(identityRepository.findByIssuerAndSubjectIdentifier(
                OidcLoginService.GOOGLE_ISSUER,
                "google-subject"
        )).thenReturn(Optional.empty());

        OidcLoginException exception = assertThrows(OidcLoginException.class, () ->
                service.resolveGoogleUser(
                        OidcLoginService.GOOGLE_ISSUER,
                        "google-subject",
                        "developer@gmail.com",
                        false
                ));

        assertEquals("email-unverified", exception.getCode());
        verify(userRepository, never()).findByEmailIgnoreCase("developer@gmail.com");
    }

    private User activeMfaUser(String email) {
        User user = new User("developer", email, "argon2-hash", UserRole.DEVELOPER);
        user.enableMfa();
        user.changeStatus(UserStatus.ACTIVE);
        return user;
    }
}
