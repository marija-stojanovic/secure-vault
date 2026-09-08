package com.securevault.honeypot.api;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

public record ConfigureHoneypotRequest(
        boolean enabled,
        @Min(1) @Max(15) int durationMinutes
) { }
