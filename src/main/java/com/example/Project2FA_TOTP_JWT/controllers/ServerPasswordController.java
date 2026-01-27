package com.example.Project2FA_TOTP_JWT.controllers;

import com.example.Project2FA_TOTP_JWT.security.services.password.ServerPasswordManagementService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/server")
public class ServerPasswordController {
    private final ServerPasswordManagementService serverPasswordManagementService;

    public ServerPasswordController(ServerPasswordManagementService serverPasswordManagementService) {
        this.serverPasswordManagementService = serverPasswordManagementService;
    }

    @GetMapping("/password")
    public ResponseEntity<String>getServerPassword(){
        return ResponseEntity.ok(serverPasswordManagementService.getCurrentPassword());
    }
}
