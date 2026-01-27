package com.example.Project2FA_TOTP_JWT.controllers;

import com.example.Project2FA_TOTP_JWT.models.User;
import com.example.Project2FA_TOTP_JWT.repositories.UserRepository;
import com.example.Project2FA_TOTP_JWT.security.totp.services.TotpAuthenticationService;
import com.example.Project2FA_TOTP_JWT.dto.JwtResponseDTO;
import com.example.Project2FA_TOTP_JWT.security.jwt.service.JwtTokenService;
import com.example.Project2FA_TOTP_JWT.dto.TotpLoginRequestDTO;
import com.example.Project2FA_TOTP_JWT.security.totp.TotpSetup;
import com.example.Project2FA_TOTP_JWT.security.services.token.TemporaryTokenService;
import com.example.Project2FA_TOTP_JWT.services.UserManagementService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/2fa")
@RequiredArgsConstructor
public class TwoFactorAuthenticationController {

    private final UserRepository userRepository;
    private final TotpAuthenticationService totpAuthenticationService;
    private final TemporaryTokenService temporaryTokenService;
    private final JwtTokenService jwtTokenService;
    private final UserManagementService userManagementService;

    // 🔹 Включение 2FA (JWT обязателен)
    @GetMapping("/setup")
    public ResponseEntity<TotpSetup> setup() {

        String username = SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getName();

        User user = userRepository.findByUsername(username)
                .orElseThrow();

        if (user.isTotpEnabled()) {
            return ResponseEntity.badRequest().build();
        }

        TotpSetup setup = totpAuthenticationService.generate(username);

        // ❗ так как temp-secret у тебя НЕТ —
        // сохраняем обычный secret
        user.setTotpSecret(setup.getSecret());
        userRepository.save(user);

        return ResponseEntity.ok(setup);
    }



    // 🔹 Подтверждение 2FA
    @PostMapping("/confirm")
    public ResponseEntity<?> confirm(@RequestBody TotpLoginRequestDTO request) {

        String username = SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getName();

        User user = userRepository.findByUsername(username)
                .orElseThrow();

        boolean valid = totpAuthenticationService.verify(
                user.getTotpSecret(),
                request.getCode()
        );

        if (!valid) {
            return ResponseEntity.badRequest().body("Неверный код");
        }

        // ✅ ВОТ ЗДЕСЬ ВКЛЮЧАЕМ
        user.setTotpEnabled(true);
        userRepository.save(user);

        return ResponseEntity.ok().build();
    }




    // 🔹 ЛОГИН ЧЕРЕЗ 2FA (БЕЗ JWT)
    @PostMapping("/login")
    public ResponseEntity<?> verifyLogin(
            @RequestBody TotpLoginRequestDTO req,
            @RequestHeader("Authorization") String authHeader) {

        // Извлекаем tempToken из заголовка
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("Требуется временный токен");
        }
        String tempToken = authHeader.substring(7);

        String username;
        try {
            username = temporaryTokenService.validateAndExtractUsername(tempToken);
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Невалидный или просроченный временный токен");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Пользователь не найден"));

        if (!totpAuthenticationService.verify(user.getTotpSecret(), req.getCode())) {
            return ResponseEntity.status(401).body("Неверный код 2FA");
        }

        String jwt = jwtTokenService.generateToken(user);

        return ResponseEntity.ok(new JwtResponseDTO(jwt, user.getRole()));
    }
}
