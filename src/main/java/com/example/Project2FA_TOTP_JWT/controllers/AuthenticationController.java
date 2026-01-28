// AuthenticationController.java - оптимизированная версия
package com.example.Project2FA_TOTP_JWT.controllers;

import com.example.Project2FA_TOTP_JWT.dto.UserDTO;
import com.example.Project2FA_TOTP_JWT.models.User;
import com.example.Project2FA_TOTP_JWT.repositories.UserRepository;
import com.example.Project2FA_TOTP_JWT.security.jwt.service.JwtTokenService;
import com.example.Project2FA_TOTP_JWT.security.services.token.TemporaryTokenService;
import com.example.Project2FA_TOTP_JWT.security.totp.SecurityTotpAuthCode;
import com.example.Project2FA_TOTP_JWT.security.totp.services.TotpAuthenticationService;
import com.example.Project2FA_TOTP_JWT.services.UserManagementService;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final long BLOCK_DURATION_MINUTES = 15;

    private final UserManagementService userManagementService;
    private final JwtTokenService jwtTokenService;
    private final TotpAuthenticationService totpAuthenticationService;
    private final TemporaryTokenService temporaryTokenService;
    private final SecurityTotpAuthCode securityTotpAuthCode;
    private final UserRepository userRepository;

    private final Map<String, LoginAttemptInfo> loginAttemptTracker = new ConcurrentHashMap<>();
    private final Map<String, LoginAttemptInfo> totpAttemptTracker = new ConcurrentHashMap<>();

    @PostMapping("/login")
    public ResponseEntity<?> handleLogin(@RequestBody UserDTO loginRequest) {
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        LoginAttemptInfo attemptInfo = loginAttemptTracker.getOrDefault(username, new LoginAttemptInfo());

        if (attemptInfo.isBlocked()) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(createErrorResponse("Too many login attempts. Please try again in 15 minutes."));
        }

        if (isInvalidCredentials(username, password)) {
            incrementAttempt(loginAttemptTracker, username);
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Username and password are required"));
        }

        Optional<User> userOptional = userManagementService.findByUsername(username);
        if (userOptional.isEmpty()) {
            incrementAttempt(loginAttemptTracker, username);
            return unauthorizedResponse("User not found");
        }

        User user = userOptional.get();

        if (!userManagementService.checkPassword(password, user.getPassword())) {
            incrementAttempt(loginAttemptTracker, username);
            return unauthorizedResponse("Invalid password");
        }

//        // Или использовать более удобный метод:
//        if (!userManagementService.verifyUserPassword(username, password)) {
//            incrementAttempt(loginAttemptTracker, username);
//            return unauthorizedResponse("Invalid password");
//        }

        loginAttemptTracker.remove(username);

        String authToken = temporaryTokenService.generate(user.getUsername());

        Map<String, Object> response = Map.of(
                "status", "success",
                "auth_token", authToken,
                "redirect", "/put_totp.html"
        );

        if (user.hasTotpSecret() && !user.isTotpEnabled()) {
            String plainSecret = securityTotpAuthCode.decrypt(user.getTotpSecret());
            GoogleAuthenticatorKey key = new GoogleAuthenticatorKey.Builder(plainSecret).build();
            String qrUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL(
                    "2FA_TOTP_App",
                    user.getUsername(),
                    key
            );

            response = Map.of(
                    "status", "success",
                    "auth_token", authToken,
                    "qr_code_url", qrUrl,
                    "secret", plainSecret,
                    "redirect", "/put_totp.html"
            );
        }

        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-totp")
    public ResponseEntity<?> verifyTotpCode(@RequestBody Map<String, String> verificationRequest) {
        String authToken = verificationRequest.get("auth_token");
        String totpCodeStr = verificationRequest.get("totp_code");

        if (authToken == null || totpCodeStr == null) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Missing required fields"));
        }

        String username;
        try {
            username = temporaryTokenService.validateAndExtractUsername(authToken);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(createErrorResponse("Invalid or expired temporary token"));
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        LoginAttemptInfo attemptInfo = totpAttemptTracker.getOrDefault(username, new LoginAttemptInfo());

        if (attemptInfo.isBlocked()) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(createErrorResponse("Too many invalid TOTP attempts. Try again in 15 minutes."));
        }

        int totpCode;
        try {
            totpCode = Integer.parseInt(totpCodeStr);
        } catch (NumberFormatException e) {
            incrementAttempt(totpAttemptTracker, username);
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Invalid TOTP code format"));
        }

        String plainSecret = securityTotpAuthCode.decrypt(user.getTotpSecret());

        if (!totpAuthenticationService.verify(plainSecret, totpCode)) {
            incrementAttempt(totpAttemptTracker, username);
            return unauthorizedResponse("Invalid TOTP code");
        }

        totpAttemptTracker.remove(username);

        user.enableTotp();
        userRepository.save(user);

        String jwtToken = jwtTokenService.generateToken(user);
        String redirectUrl = user.isAdmin() ? "/users.html" : "/index.html";

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "token", jwtToken,
                "redirect", redirectUrl
        ));
    }

    private boolean isInvalidCredentials(String username, String password) {
        return username == null || username.trim().isEmpty() ||
                password == null || password.trim().isEmpty();
    }

    private Map<String, String> createErrorResponse(String message) {
        return Map.of("status", "error", "error", message);
    }

    private ResponseEntity<Map<String, String>> unauthorizedResponse(String message) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(createErrorResponse(message));
    }

    private void incrementAttempt(Map<String, LoginAttemptInfo> tracker, String username) {
        LoginAttemptInfo info = tracker.computeIfAbsent(username, k -> new LoginAttemptInfo());
        info.incrementAttempt();
        if (info.getAttemptCount() >= MAX_LOGIN_ATTEMPTS) {
            info.blockUntil(Instant.now().plusSeconds(BLOCK_DURATION_MINUTES * 60));
        }
    }

    private static class LoginAttemptInfo {
        private int attemptCount;
        private Instant blockedUntil;

        boolean isBlocked() {
            return blockedUntil != null && Instant.now().isBefore(blockedUntil);
        }

        int getAttemptCount() {
            return attemptCount;
        }

        void incrementAttempt() {
            attemptCount++;
        }

        void blockUntil(Instant until) {
            this.blockedUntil = until;
        }
    }
}