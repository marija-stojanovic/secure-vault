package com.securevault.security;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/admin/blocked-ips")
public class BlockedIpAdminController {

    private final BlockedIpAdminService service;

    public BlockedIpAdminController(BlockedIpAdminService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<List<BlockedIpAdminService.BlockedIpResponse>> activeBlocks() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.activeBlocks());
    }

    @DeleteMapping("/{ipAddress}")
    public ResponseEntity<Void> unblock(@PathVariable String ipAddress) {
        service.unblock(ipAddress);
        return ResponseEntity.noContent().build();
    }
}
