// User.java - добавлены хелпер-методы
package com.example.Project2FA_TOTP_JWT.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users") // Изменено имя таблицы для избежания конфликтов
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 50)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String role = "USER";

    private String totpSecret;

    private boolean totpEnabled = false;

    // Хелпер-методы для лучшей читаемости кода
    public boolean hasTotpSecret() {
        return totpSecret != null && !totpSecret.trim().isEmpty();
    }

    public boolean isAdmin() {
        return "ADMIN".equals(role);
    }

    public void enableTotp() {
        this.totpEnabled = true;
    }

    public void disableTotp() {
        this.totpEnabled = false;
    }
}