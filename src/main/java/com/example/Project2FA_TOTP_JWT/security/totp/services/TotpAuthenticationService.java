package com.example.Project2FA_TOTP_JWT.security.totp.services;

import com.example.Project2FA_TOTP_JWT.security.totp.TotpSetup;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Service;

@Service
public class TotpAuthenticationService {
    private final GoogleAuthenticator googleAuthenticator;

    public TotpAuthenticationService() {
        this.googleAuthenticator = new GoogleAuthenticator();
    }

    public TotpSetup generate(String username){
        GoogleAuthenticatorKey googleAuthenticatorKey=googleAuthenticator.createCredentials();
        String secret=googleAuthenticatorKey.getKey();
        String url= GoogleAuthenticatorQRGenerator.getOtpAuthURL(
                "2FA_TOTP",
                username,
                googleAuthenticatorKey
        );

        return new TotpSetup(secret,url);
    }

    public boolean verify(String secret,int code){
        return googleAuthenticator.authorize(secret,code);
    }
}
