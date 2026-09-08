package com.securevault.health;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HealthControllerTest {

    private final HealthController controller = new HealthController();

    @Test
    void reportsBackendAsUp() {
        HealthController.HealthResponse response = controller.health();

        assertEquals("UP", response.status());
        assertEquals("secure-vault-backend", response.service());
    }
}
