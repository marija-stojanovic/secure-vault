package com.securevault.gateway;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class GatewayHealthController {

    @GetMapping("/gateway/health")
    Map<String, String> health() {
        return Map.of("status", "UP", "service", "secure-vault-gateway");
    }
}
