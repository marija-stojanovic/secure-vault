package com.securevault.honeypot;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;

@Configuration
public class HoneypotSeedConfiguration {

    @Bean
    ApplicationRunner seedHoneytokens(HoneytokenRepository repository) {
        return arguments -> {
            if (repository.count() > 0) return;
            SecureRandom random = new SecureRandom();
            for (String name : List.of("production-root-key", "legacy-database-admin", "emergency-backup-token")) {
                byte[] decoyBlob = new byte[96];
                random.nextBytes(decoyBlob);
                byte[] fingerprint = MessageDigest.getInstance("SHA-256")
                        .digest((name + ":secure-vault-honeytoken").getBytes(StandardCharsets.UTF_8));
                repository.save(new Honeytoken(name, decoyBlob, fingerprint));
            }
        };
    }
}
