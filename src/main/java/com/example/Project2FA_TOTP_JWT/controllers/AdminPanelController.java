// AdminPanelController.java - улучшенная версия
package com.example.Project2FA_TOTP_JWT.controllers;

import com.example.Project2FA_TOTP_JWT.dto.UserDTO;
import com.example.Project2FA_TOTP_JWT.models.User;
import com.example.Project2FA_TOTP_JWT.security.totp.SecurityTotpAuthCode;
import com.example.Project2FA_TOTP_JWT.services.UserManagementService;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminPanelController {

    private static final int MIN_USERNAME_LENGTH = 3;
    private static final int MAX_USERNAME_LENGTH = 50;
    private static final int MIN_PASSWORD_LENGTH = 6;

    private final UserManagementService userManagementService;
    private final SecurityTotpAuthCode securityTotpAuthCode;

    @GetMapping("/users")
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        return ResponseEntity.ok(userManagementService.getAllUsers());
    }

    @PostMapping("/users")
    public ResponseEntity<?> createUser(@RequestBody UserDTO userRequest) {
        try {
            validateUserRequest(userRequest);

            if (userManagementService.findByUsername(userRequest.getUsername()).isPresent()) {
                return badRequestResponse("User with this username already exists");
            }

            UserDTO createdUser = userManagementService.createUser(userRequest);
            return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);

        } catch (IllegalArgumentException e) {
            return badRequestResponse(e.getMessage());
        } catch (Exception e) {
            return serverErrorResponse("Error creating user: " + e.getMessage());
        }
    }

    @DeleteMapping("/users/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable Long userId) {
        try {
            userManagementService.deleteUser(userId);
            return ResponseEntity.ok().build();
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(createErrorResponse(e.getMessage()));
        }
    }

    @GetMapping("/users/{userId}/qr")
    public ResponseEntity<?> getUserQrCode(@PathVariable Long userId) {
        Optional<User> userOptional = userManagementService.findById(userId);
        if (userOptional.isEmpty()) {
            return notFoundResponse("User not found");
        }

        User user = userOptional.get();
        if (!user.hasTotpSecret()) {
            return badRequestResponse("TOTP secret not configured for user");
        }

        String plainSecret = securityTotpAuthCode.decrypt(user.getTotpSecret());
        GoogleAuthenticatorKey key = new GoogleAuthenticatorKey.Builder(plainSecret).build();
        String qrCodeUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL(
                "My2FA-App",
                user.getUsername(),
                key
        );

        return ResponseEntity.ok(Map.of("qr_code_url", qrCodeUrl));
    }

    private void validateUserRequest(UserDTO request) {
        if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
            throw new IllegalArgumentException("Username is required");
        }

        if (request.getPassword() == null || request.getPassword().trim().isEmpty()) {
            throw new IllegalArgumentException("Password is required");
        }

        String username = request.getUsername().trim();
        if (username.length() < MIN_USERNAME_LENGTH || username.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Username must be between %d and %d characters",
                            MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH)
            );
        }

        if (request.getPassword().length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Password must be at least %d characters", MIN_PASSWORD_LENGTH)
            );
        }
    }

    private ResponseEntity<?> badRequestResponse(String message) {
        return ResponseEntity.badRequest()
                .body(createErrorResponse(message));
    }

    private ResponseEntity<?> notFoundResponse(String message) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(createErrorResponse(message));
    }

    private ResponseEntity<?> serverErrorResponse(String message) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(createErrorResponse(message));
    }

    private Map<String, String> createErrorResponse(String error) {
        return Map.of("status", "error", "error", error);
    }
}