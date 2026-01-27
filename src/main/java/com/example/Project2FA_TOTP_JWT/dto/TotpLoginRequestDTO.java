package com.example.Project2FA_TOTP_JWT.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// security/jwt/dto/TotpLoginRequest.java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TotpLoginRequestDTO {
    private int code;   // только код!
}

