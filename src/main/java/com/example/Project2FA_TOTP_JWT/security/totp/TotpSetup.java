package com.example.Project2FA_TOTP_JWT.security.totp;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TotpSetup {
    private String secret;
    private String qrUrl;
}
