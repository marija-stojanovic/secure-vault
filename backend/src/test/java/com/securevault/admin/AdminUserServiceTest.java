package com.securevault.admin;

import com.securevault.auth.AuthException;
import com.securevault.auth.SessionService;
import com.securevault.user.User;
import com.securevault.user.UserRepository;
import com.securevault.user.UserRole;
import com.securevault.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AdminUserServiceTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final AdminUserService service = new AdminUserService(userRepository, sessionService);

    @Test
    void promotesActiveDeveloperToTeamLead() {
        User developer = new User("developer", "developer@example.com", "hash", UserRole.DEVELOPER);
        ReflectionTestUtils.setField(developer, "id", 7L);
        developer.changeStatus(UserStatus.ACTIVE);
        when(userRepository.findById(7L)).thenReturn(Optional.of(developer));

        var response = service.promoteToTeamLead(7L);

        assertEquals(UserRole.TEAM_LEAD, developer.getRole());
        assertEquals("TEAM_LEAD", response.role());
    }

    @Test
    void rejectsPromotionOfNonDeveloper() {
        User teamLead = new User("lead", "lead@example.com", "hash", UserRole.TEAM_LEAD);
        ReflectionTestUtils.setField(teamLead, "id", 8L);
        teamLead.changeStatus(UserStatus.ACTIVE);
        when(userRepository.findById(8L)).thenReturn(Optional.of(teamLead));

        assertThrows(AuthException.class, () -> service.promoteToTeamLead(8L));
    }

    @Test
    void demotesActiveTeamLeadToDeveloper() {
        User teamLead = new User("lead2", "lead2@example.com", "hash", UserRole.TEAM_LEAD);
        ReflectionTestUtils.setField(teamLead, "id", 9L);
        teamLead.changeStatus(UserStatus.ACTIVE);
        when(userRepository.findById(9L)).thenReturn(Optional.of(teamLead));

        var response = service.demoteToDeveloper(9L);

        assertEquals(UserRole.DEVELOPER, teamLead.getRole());
        assertEquals("DEVELOPER", response.role());
    }

    @Test
    void freezesUserAndRevokesAllSessions() {
        User admin = user(1L, "admin", UserRole.ADMIN, UserStatus.ACTIVE);
        User developer = user(10L, "developer2", UserRole.DEVELOPER, UserStatus.ACTIVE);
        when(userRepository.findById(10L)).thenReturn(Optional.of(developer));

        var response = service.freeze(10L, admin);

        assertEquals(UserStatus.FROZEN, developer.getStatus());
        assertEquals("FROZEN", response.status());
        verify(sessionService).revokeAllForUser(10L);
    }

    @Test
    void doesNotAllowDisabledUserToBeUnfrozen() {
        User admin = user(1L, "admin2", UserRole.ADMIN, UserStatus.ACTIVE);
        User developer = user(11L, "developer3", UserRole.DEVELOPER, UserStatus.DISABLED);
        when(userRepository.findById(11L)).thenReturn(Optional.of(developer));

        assertThrows(AuthException.class, () -> service.unfreeze(11L, admin));
        assertEquals(UserStatus.DISABLED, developer.getStatus());
    }

    @Test
    void preventsAdminFromDisablingOwnAccount() {
        User admin = user(1L, "admin3", UserRole.ADMIN, UserStatus.ACTIVE);
        when(userRepository.findById(1L)).thenReturn(Optional.of(admin));

        assertThrows(AuthException.class, () -> service.disable(1L, admin));
    }

    private User user(long id, String username, UserRole role, UserStatus status) {
        User user = new User(username, username + "@example.com", "hash", role);
        ReflectionTestUtils.setField(user, "id", id);
        user.changeStatus(status);
        return user;
    }
}
