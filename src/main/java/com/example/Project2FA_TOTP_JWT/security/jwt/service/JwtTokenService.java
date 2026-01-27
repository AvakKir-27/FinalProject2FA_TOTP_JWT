package com.example.Project2FA_TOTP_JWT.security.jwt.service;

import com.example.Project2FA_TOTP_JWT.models.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

// JwtTokenService.java - упрощенная версия для совместимости
@Service
public class JwtTokenService {
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-token.expiration:3600}")
    private long expirationSeconds;

    private SecretKey getSignKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(User user) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(expirationSeconds);

        return Jwts.builder()
                .subject(user.getUsername())
                .claim("role", user.getRole())
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .signWith(getSignKey())
                .compact();
    }

    public boolean isValid(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSignKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
