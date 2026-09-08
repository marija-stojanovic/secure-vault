package com.securevault.admin;

import com.securevault.admin.api.AdminUserResponse;
import com.securevault.auth.AuthException;
import com.securevault.auth.SessionService;
import com.securevault.user.User;
import com.securevault.user.UserRepository;
import com.securevault.user.UserRole;
import com.securevault.user.UserStatus;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AdminUserService {

    private final UserRepository userRepository;
    private final SessionService sessionService;

    public AdminUserService(UserRepository userRepository, SessionService sessionService) {
        this.userRepository = userRepository;
        this.sessionService = sessionService;
    }

    @Transactional(readOnly = true)
    public List<AdminUserResponse> listUsers() {
        return userRepository.findAll(Sort.by(Sort.Direction.ASC, "username"))
                .stream()
                .map(this::response)
                .toList();
    }

    @Transactional
    public AdminUserResponse promoteToTeamLead(long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(HttpStatus.NOT_FOUND, "Korisnik nije pronađen"));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AuthException(HttpStatus.CONFLICT, "Samo aktivan korisnik može biti Team Lead");
        }
        if (user.getRole() != UserRole.DEVELOPER) {
            throw new AuthException(HttpStatus.CONFLICT, "Samo Developer može biti promovisan u Team Lead");
        }

        user.changeRole(UserRole.TEAM_LEAD);
        return response(user);
    }

    @Transactional
    public AdminUserResponse demoteToDeveloper(long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(HttpStatus.NOT_FOUND, "Korisnik nije pronađen"));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AuthException(HttpStatus.CONFLICT, "Samo aktivan korisnik može promijeniti ulogu");
        }
        if (user.getRole() != UserRole.TEAM_LEAD) {
            throw new AuthException(HttpStatus.CONFLICT, "Samo Team Lead može biti vraćen u Developer ulogu");
        }

        user.changeRole(UserRole.DEVELOPER);
        return response(user);
    }

    @Transactional
    public AdminUserResponse freeze(long userId, User administrator) {
        User user = manageableUser(userId, administrator);
        requireStatus(user, UserStatus.ACTIVE, "Samo aktivan nalog može biti zamrznut");
        user.changeStatus(UserStatus.FROZEN);
        sessionService.revokeAllForUser(userId);
        return response(user);
    }

    @Transactional
    public AdminUserResponse unfreeze(long userId, User administrator) {
        User user = manageableUser(userId, administrator);
        requireStatus(user, UserStatus.FROZEN, "Samo zamrznut nalog može biti odmrznut");
        user.changeStatus(UserStatus.ACTIVE);
        user.clearLoginLock();
        return response(user);
    }

    @Transactional
    public AdminUserResponse disable(long userId, User administrator) {
        User user = manageableUser(userId, administrator);
        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.PENDING) {
            throw new AuthException(HttpStatus.CONFLICT, "Nalog nije moguće deaktivirati u trenutnom stanju");
        }
        user.changeStatus(UserStatus.DISABLED);
        sessionService.revokeAllForUser(userId);
        return response(user);
    }

    @Transactional
    public AdminUserResponse unlock(long userId, User administrator) {
        User user = manageableUser(userId, administrator);
        requireStatus(user, UserStatus.ACTIVE, "Samo aktivan nalog može biti otključan");
        if (user.getFailedLoginAttempts() == 0 && user.getLockedUntil() == null) {
            throw new AuthException(HttpStatus.CONFLICT, "Nalog nije privremeno zaključan");
        }
        user.clearLoginLock();
        return response(user);
    }

    @Transactional
    public AdminUserResponse revokeSessions(long userId, User administrator) {
        User user = manageableUser(userId, administrator);
        sessionService.revokeAllForUser(userId);
        return response(user);
    }

    private User manageableUser(long userId, User administrator) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(HttpStatus.NOT_FOUND, "Korisnik nije pronađen"));
        if (user.getId().equals(administrator.getId()) || user.getRole() == UserRole.ADMIN) {
            throw new AuthException(HttpStatus.CONFLICT, "Admin ne može ovom operacijom promijeniti vlastiti ili drugi Admin nalog");
        }
        return user;
    }

    private void requireStatus(User user, UserStatus status, String message) {
        if (user.getStatus() != status) throw new AuthException(HttpStatus.CONFLICT, message);
    }

    private AdminUserResponse response(User user) {
        return AdminUserResponse.from(user, sessionService.countActiveForUser(user.getId()));
    }
}
