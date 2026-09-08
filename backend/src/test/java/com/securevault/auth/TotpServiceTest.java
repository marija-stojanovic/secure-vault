package com.securevault.auth;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.OptionalLong;

import static org.junit.jupiter.api.Assertions.assertTrue;

class TotpServiceTest {

    @Test
    void acceptsCurrentCodeAndRejectsItsReuse() throws Exception {
        Instant now = Instant.parse("2026-08-21T12:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        TotpService service = new TotpService(clock, "SecureVault");
        TotpService.TotpSetup setup = service.createSetup("developer");
        TimeBasedOneTimePasswordGenerator generator =
                new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 6, "HmacSHA1");
        String code = generator.generateOneTimePasswordString(
                new SecretKeySpec(setup.secret(), "HmacSHA1"),
                now
        );

        OptionalLong firstUse = service.verify(setup.secret(), code, null);
        OptionalLong replay = service.verify(setup.secret(), code, firstUse.getAsLong());

        assertTrue(firstUse.isPresent());
        assertTrue(replay.isEmpty());
    }
}
