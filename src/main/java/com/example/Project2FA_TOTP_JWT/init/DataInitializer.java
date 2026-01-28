package com.example.Project2FA_TOTP_JWT.init;

import com.example.Project2FA_TOTP_JWT.models.User;
import com.example.Project2FA_TOTP_JWT.repositories.UserRepository;

import com.example.Project2FA_TOTP_JWT.role.Role;
import com.example.Project2FA_TOTP_JWT.security.totp.SecurityTotpAuthCode;
import com.example.Project2FA_TOTP_JWT.security.totp.TotpSetup;
import com.example.Project2FA_TOTP_JWT.security.totp.services.TotpAuthenticationService;
import jakarta.annotation.PostConstruct;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TotpAuthenticationService totpAuthenticationService;
    private final SecurityTotpAuthCode securityTotpAuthCode;  // ← добавляем наш шифратор

    public DataInitializer(UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           TotpAuthenticationService totpAuthenticationService,
                           SecurityTotpAuthCode securityTotpAuthCode) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.totpAuthenticationService = totpAuthenticationService;
        this.securityTotpAuthCode = securityTotpAuthCode;
    }

    @PostConstruct
    public void init() {
        if (userRepository.findByUsername("admin").isEmpty()) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setRole(Role.ADMIN);

            // Генерируем секрет
            TotpSetup setup = totpAuthenticationService.generate("admin");
            String plainSecret = setup.getSecret();

            // Шифруем секрет перед сохранением
            String encryptedSecret = securityTotpAuthCode.encrypt(plainSecret);
            admin.setTotpSecret(encryptedSecret);

            userRepository.save(admin);
            System.out.println("Администратор создан успешно! Зашифрованный секрет сохранён.");
        }
    }
}