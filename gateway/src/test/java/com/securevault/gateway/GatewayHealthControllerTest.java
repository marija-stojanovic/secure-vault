package com.securevault.gateway;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GatewayHealthControllerTest {

    @Test
    void reportsGatewayAsUp() {
        var response = new GatewayHealthController().health();
        assertEquals("UP", response.get("status"));
        assertEquals("secure-vault-gateway", response.get("service"));
    }
}
