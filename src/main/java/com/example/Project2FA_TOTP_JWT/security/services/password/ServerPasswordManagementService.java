package com.example.Project2FA_TOTP_JWT.security.services.password;

import lombok.Data;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@Data
public class ServerPasswordManagementService {
    private volatile String currentPassword=generateNewPassword();
    @Scheduled(fixedRate = 30000*5) // каждые 60 секунд
    public void updatePassword() {
        currentPassword = generateNewPassword();
        System.out.println("Новый серверный пароль: " + currentPassword);
    }

    private String generateNewPassword(){
        return UUID.randomUUID().toString().replaceAll("-", "").substring(0, 16);
    }

}
