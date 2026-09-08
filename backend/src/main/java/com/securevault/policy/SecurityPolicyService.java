package com.securevault.policy;

import com.securevault.policy.api.SecurityPolicyResponse;
import com.securevault.policy.api.UpdateSecurityPolicyRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.securevault.vault.Secret;
import com.securevault.vault.SecretRepository;

import java.time.Clock;

@Service
public class SecurityPolicyService {

    private final SecurityPolicyRepository repository;
    private final SecretRepository secretRepository;
    private final Clock clock;

    public SecurityPolicyService(SecurityPolicyRepository repository, SecretRepository secretRepository, Clock clock) {
        this.repository = repository;
        this.secretRepository = secretRepository;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public SecurityPolicyResponse current() {
        return SecurityPolicyResponse.from(requirePolicy());
    }

    @Transactional
    public SecurityPolicyResponse update(UpdateSecurityPolicyRequest request) {
        SecurityPolicy policy = requirePolicy();
        policy.updateManagedRules(
                request.minimumLoginPasswordLength(),
                request.minimumMasterPasswordLength(),
                request.maximumFailedLoginAttempts(),
                request.secretRotationDays()
        );
        recalculateRotationDeadlines(request.secretRotationDays());
        return SecurityPolicyResponse.from(policy);
    }

    private void recalculateRotationDeadlines(short rotationDays) {
        long rotationSeconds = rotationDays * 86_400L;
        for (Secret secret : secretRepository.findAllByDeletedAtIsNull()) {
            if (secret.getUpdatedAt() == null) {
                secret.scheduleRotation(clock.instant().plusSeconds(rotationSeconds));
            } else {
                secret.scheduleRotation(secret.getUpdatedAt().plusSeconds(rotationSeconds));
            }
        }
    }

    private SecurityPolicy requirePolicy() {
        return repository.findFirstByOrderByIdAsc()
                .orElseThrow(() -> new IllegalStateException("Security policy is missing"));
    }
}
