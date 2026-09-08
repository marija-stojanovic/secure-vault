package com.securevault.auth;

import com.securevault.auth.api.ClientCryptoMaterialRequest;
import com.securevault.auth.api.MfaConfirmationRequest;
import com.securevault.auth.api.RegistrationRequest;
import com.securevault.auth.api.RegistrationResponse;
import com.securevault.user.User;
import com.securevault.user.UserCryptoMaterial;
import com.securevault.user.UserCryptoMaterialRepository;
import com.securevault.user.UserRepository;
import com.securevault.user.UserRole;
import com.securevault.user.UserStatus;
import com.securevault.policy.SecurityPolicy;
import com.securevault.policy.SecurityPolicyRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.OptionalLong;

@Service
public class RegistrationService {

    private static final int MINIMUM_RSA_BITS = 3072;
    private static final int MAXIMUM_ENCRYPTED_PRIVATE_KEY_BYTES = 1_048_576;

    private final UserRepository userRepository;
    private final UserCryptoMaterialRepository cryptoMaterialRepository;
    private final UserMfaRepository userMfaRepository;
    private final PasswordEncoder passwordEncoder;
    private final TotpService totpService;
    private final MfaSecretCryptoService mfaSecretCryptoService;
    private final Clock clock;
    private final SecurityPolicyRepository policyRepository;

    public RegistrationService(
            UserRepository userRepository,
            UserCryptoMaterialRepository cryptoMaterialRepository,
            UserMfaRepository userMfaRepository,
            PasswordEncoder passwordEncoder,
            TotpService totpService,
            MfaSecretCryptoService mfaSecretCryptoService,
            Clock clock,
            SecurityPolicyRepository policyRepository
    ) {
        this.userRepository = userRepository;
        this.cryptoMaterialRepository = cryptoMaterialRepository;
        this.userMfaRepository = userMfaRepository;
        this.passwordEncoder = passwordEncoder;
        this.totpService = totpService;
        this.mfaSecretCryptoService = mfaSecretCryptoService;
        this.clock = clock;
        this.policyRepository = policyRepository;
    }

    @Transactional
    public RegistrationResponse register(RegistrationRequest request) {
        String username = request.username().trim();
        String email = request.email().trim().toLowerCase();

        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw new AuthException(HttpStatus.CONFLICT, "Korisničko ime je već zauzeto");
        }
        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new AuthException(HttpStatus.CONFLICT, "Email adresa je već registrovana");
        }
        SecurityPolicy policy = policyRepository.findFirstByOrderByIdAsc()
                .orElseThrow(() -> new IllegalStateException("Security policy is missing"));
        if (request.loginPassword().length() < policy.getMinimumLoginPasswordLength()) {
            throw new AuthException(HttpStatus.BAD_REQUEST,
                    "Login lozinka mora imati najmanje " + policy.getMinimumLoginPasswordLength() + " znakova");
        }

        DecodedCryptoMaterial crypto = decodeAndValidate(request.cryptoMaterial());
        User user = new User(
                username,
                email,
                passwordEncoder.encode(request.loginPassword()),
                UserRole.DEVELOPER
        );
        userRepository.save(user);

        return finishSecuritySetup(user, request.cryptoMaterial(), crypto);
    }

    /**
     * Completes the zero-knowledge and MFA setup for an account that was created
     * automatically by a verified Google OIDC login.
     */
    @Transactional
    public RegistrationResponse setupOidcUser(long userId, ClientCryptoMaterialRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(HttpStatus.UNAUTHORIZED, "OIDC registracija nije ispravna"));

        if (user.getStatus() != UserStatus.PENDING || user.getLoginPasswordHash() != null) {
            throw new AuthException(HttpStatus.CONFLICT, "Sigurnosna postavka naloga je već završena");
        }
        if (cryptoMaterialRepository.existsById(userId) || userMfaRepository.existsById(userId)) {
            throw new AuthException(HttpStatus.CONFLICT, "Sigurnosna postavka naloga je već započeta");
        }

        DecodedCryptoMaterial crypto = decodeAndValidate(request);
        return finishSecuritySetup(user, request, crypto);
    }

    private RegistrationResponse finishSecuritySetup(
            User user,
            ClientCryptoMaterialRequest request,
            DecodedCryptoMaterial crypto
    ) {
        cryptoMaterialRepository.save(new UserCryptoMaterial(
                user,
                "PBKDF2-SHA-256",
                crypto.kdfSalt(),
                request.kdfIterations(),
                "RSA-OAEP-3072",
                crypto.publicKeySpki(),
                crypto.encryptedPrivateKey(),
                crypto.privateKeyIv(),
                "AES-256-GCM",
                (short) 1
        ));

        TotpService.TotpSetup totpSetup = totpService.createSetup(user.getUsername());
        MfaSecretCryptoService.EncryptedSecret encryptedTotp =
                mfaSecretCryptoService.encrypt(totpSetup.secret());
        userMfaRepository.save(new UserMfa(
                user,
                encryptedTotp.ciphertext(),
                encryptedTotp.iv()
        ));

        return new RegistrationResponse(
                user.getId(),
                user.getUsername(),
                user.getStatus().name(),
                totpSetup.base32Secret(),
                totpSetup.provisioningUri()
        );
    }

    @Transactional
    public void confirmMfa(MfaConfirmationRequest request) {
        User user = userRepository.findByUsernameIgnoreCase(request.username().trim())
                .orElseThrow(() -> invalidMfaCode());
        UserMfa userMfa = userMfaRepository.findById(user.getId())
                .orElseThrow(() -> invalidMfaCode());

        if (userMfa.getConfirmedAt() != null) {
            throw new AuthException(HttpStatus.CONFLICT, "MFA je već potvrđen");
        }

        byte[] secret = mfaSecretCryptoService.decrypt(
                userMfa.getEncryptedTotpSecret(),
                userMfa.getEncryptionIv()
        );
        OptionalLong usedStep = totpService.verify(secret, request.code(), null);
        if (usedStep.isEmpty()) {
            throw invalidMfaCode();
        }

        Instant now = Instant.now(clock);
        userMfa.confirm(now, usedStep.getAsLong());
        user.enableMfa();
        user.changeStatus(UserStatus.ACTIVE);
    }

    private DecodedCryptoMaterial decodeAndValidate(ClientCryptoMaterialRequest request) {
        try {
            byte[] salt = Base64.getDecoder().decode(request.kdfSaltBase64());
            byte[] publicKey = Base64.getDecoder().decode(request.publicKeySpkiBase64());
            byte[] encryptedPrivateKey = Base64.getDecoder().decode(request.encryptedPrivateKeyBase64());
            byte[] iv = Base64.getDecoder().decode(request.privateKeyIvBase64());

            if (salt.length < 16 || salt.length > 64) {
                throw invalidCryptoMaterial();
            }
            if (iv.length != 12) {
                throw invalidCryptoMaterial();
            }
            if (encryptedPrivateKey.length < 32
                    || encryptedPrivateKey.length > MAXIMUM_ENCRYPTED_PRIVATE_KEY_BYTES) {
                throw invalidCryptoMaterial();
            }
            validateRsaPublicKey(publicKey);
            return new DecodedCryptoMaterial(salt, publicKey, encryptedPrivateKey, iv);
        } catch (IllegalArgumentException exception) {
            throw invalidCryptoMaterial();
        }
    }

    private void validateRsaPublicKey(byte[] encodedKey) {
        try {
            RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(encodedKey));
            if (key.getModulus().bitLength() < MINIMUM_RSA_BITS) {
                throw invalidCryptoMaterial();
            }
        } catch (GeneralSecurityException | ClassCastException exception) {
            throw invalidCryptoMaterial();
        }
    }

    private AuthException invalidCryptoMaterial() {
        return new AuthException(HttpStatus.BAD_REQUEST, "Kriptografski materijal nije ispravan");
    }

    private AuthException invalidMfaCode() {
        return new AuthException(HttpStatus.UNAUTHORIZED, "MFA kod nije ispravan");
    }

    private record DecodedCryptoMaterial(
            byte[] kdfSalt,
            byte[] publicKeySpki,
            byte[] encryptedPrivateKey,
            byte[] privateKeyIv
    ) {
    }
}
