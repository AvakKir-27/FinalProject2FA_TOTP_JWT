package com.example.Project2FA_TOTP_JWT.dto;


import com.example.Project2FA_TOTP_JWT.role.Role;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JwtResponseDTO {
    private String token;
    private Role role;
}
