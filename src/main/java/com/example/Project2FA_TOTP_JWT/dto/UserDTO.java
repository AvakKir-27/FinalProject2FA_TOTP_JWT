package com.example.Project2FA_TOTP_JWT.dto;

import lombok.Data;

@Data
public class UserDTO {
    private Long id;
    private String username;
    private String password;
    private String role;

}
