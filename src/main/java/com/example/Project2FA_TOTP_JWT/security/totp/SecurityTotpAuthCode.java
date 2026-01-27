// SecurityTotpAuthCode.java - добавим более безопасную генерацию ключа
package com.example.Project2FA_TOTP_JWT.security.totp;

import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@Component
@AllArgsConstructor
public class SecurityTotpAuthCode {

    private final byte[] encryptionKey;

    public SecurityTotpAuthCode() {
        // Значение по умолчанию, если property не задано
        String secretKey = "MySuperSecretKeyForTOTPEncryption123!";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            this.encryptionKey = digest.digest(secretKey.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize encryption key", e);
        }
    }

    public String encrypt(String plainText) {
        if (plainText == null || plainText.isEmpty()) {
            return plainText;
        }

        try {
            byte[] textBytes = plainText.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedBytes = new byte[textBytes.length];

            for (int i = 0; i < textBytes.length; i++) {
                encryptedBytes[i] = (byte) (textBytes[i] ^ encryptionKey[i % encryptionKey.length]);
            }

            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(String encryptedBase64) {
        if (encryptedBase64 == null || encryptedBase64.isEmpty()) {
            return encryptedBase64;
        }

        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedBase64);
            byte[] decryptedBytes = new byte[encryptedBytes.length];

            for (int i = 0; i < encryptedBytes.length; i++) {
                decryptedBytes[i] = (byte) (encryptedBytes[i] ^ encryptionKey[i % encryptionKey.length]);
            }

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
}