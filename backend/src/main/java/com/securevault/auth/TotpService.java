package com.securevault.auth;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.codec.binary.Base32;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.OptionalLong;

@Service
public class TotpService {

    private static final Duration TIME_STEP = Duration.ofSeconds(30);
    private static final int PASSWORD_LENGTH = 6;
    private static final String HMAC_ALGORITHM = "HmacSHA1";

    private final TimeBasedOneTimePasswordGenerator generator;
    private final Clock clock;
    private final String issuer;
    private final Base32 base32 = new Base32();

    public TotpService(Clock clock, @Value("${app.security.totp-issuer}") String issuer) {
        this.clock = clock;
        this.issuer = issuer;
        this.generator = new TimeBasedOneTimePasswordGenerator(
                TIME_STEP,
                PASSWORD_LENGTH,
                HMAC_ALGORITHM
        );
    }

    public TotpSetup createSetup(String username) {
        byte[] secret = generateSecret();
        String base32Secret = base32.encodeToString(secret).replace("=", "");
        String label = urlEncode(issuer + ":" + username);
        String uri = "otpauth://totp/" + label
                + "?secret=" + base32Secret
                + "&issuer=" + urlEncode(issuer)
                + "&algorithm=SHA1&digits=6&period=30";
        return new TotpSetup(secret, base32Secret, uri);
    }

    public OptionalLong verify(byte[] secret, String submittedCode, Long lastUsedTimeStep) {
        if (submittedCode == null || !submittedCode.matches("\\d{6}")) {
            return OptionalLong.empty();
        }

        long currentStep = Math.floorDiv(clock.instant().getEpochSecond(), TIME_STEP.toSeconds());
        SecretKey key = new SecretKeySpec(secret, HMAC_ALGORITHM);

        for (long step = currentStep - 1; step <= currentStep + 1; step++) {
            if (lastUsedTimeStep != null && step <= lastUsedTimeStep) {
                continue;
            }

            Instant stepInstant = Instant.ofEpochSecond(step * TIME_STEP.toSeconds());
            String expected;
            try {
                expected = generator.generateOneTimePasswordString(key, stepInstant);
            } catch (GeneralSecurityException exception) {
                throw new IllegalStateException("Unable to verify TOTP code", exception);
            }
            if (MessageDigest.isEqual(
                    expected.getBytes(StandardCharsets.US_ASCII),
                    submittedCode.getBytes(StandardCharsets.US_ASCII)
            )) {
                return OptionalLong.of(step);
            }
        }
        return OptionalLong.empty();
    }

    private byte[] generateSecret() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(generator.getAlgorithm());
            int macLengthInBytes = Mac.getInstance(generator.getAlgorithm()).getMacLength();
            keyGenerator.init(macLengthInBytes * 8);
            return keyGenerator.generateKey().getEncoded();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to generate TOTP secret", exception);
        }
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    public record TotpSetup(byte[] secret, String base32Secret, String provisioningUri) {
        public TotpSetup {
            secret = secret.clone();
        }
    }
}
