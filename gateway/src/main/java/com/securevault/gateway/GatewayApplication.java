package com.securevault.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;

@SpringBootApplication
public class GatewayApplication {

    public static void main(String[] args) {
        configureBackendCertificateTrust();
        SpringApplication.run(GatewayApplication.class, args);
    }

    private static void configureBackendCertificateTrust() {
        String password = System.getenv().getOrDefault(
                "GATEWAY_TLS_TRUSTSTORE_PASSWORD",
                "securevault"
        );

        try (InputStream truststoreStream = GatewayApplication.class.getResourceAsStream(
                "/tls/gateway-truststore.p12"
        )) {
            if (truststoreStream == null) {
                throw new IllegalStateException("Gateway TLS truststore nije pronadjen.");
            }

            KeyStore truststore = KeyStore.getInstance("PKCS12");
            truststore.load(truststoreStream, password.toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm()
            );
            trustManagerFactory.init(truststore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
            SSLContext.setDefault(sslContext);
        } catch (Exception exception) {
            throw new IllegalStateException("Gateway ne moze ucitati povjerenje za backend TLS certifikat.", exception);
        }
    }
}
