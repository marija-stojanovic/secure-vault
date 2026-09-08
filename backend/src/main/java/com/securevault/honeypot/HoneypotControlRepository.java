package com.securevault.honeypot;

import org.springframework.data.jpa.repository.JpaRepository;

public interface HoneypotControlRepository extends JpaRepository<HoneypotControl, Integer> {
}
