// TemporaryTokenService.java - улучшенная версия
package com.example.Project2FA_TOTP_JWT.security.services.token;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class TemporaryTokenService {

    private static final String TOKEN_TYPE = "2fa_temp";

    private final SecretKey secretKey;
    private final long expirationMs;

    public TemporaryTokenService(
            @Value("${jwt.temp-token.secret}") String secret,
            @Value("${jwt.temp-token.expiration:300000}") long expirationMs) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    public String generate(String username) {
        Instant now = Instant.now();
        Instant expiryDate = now.plus(expirationMs, ChronoUnit.MILLIS);

        Map<String, Object> claims = new HashMap<>();
        claims.put("tokenType", TOKEN_TYPE);
        claims.put("purpose", "two_factor_auth");

        return Jwts.builder()
                .subject(username)
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiryDate))
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    public String validateAndExtractUsername(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String tokenType = claims.get("tokenType", String.class);
            if (!TOKEN_TYPE.equals(tokenType)) {
                throw new SecurityException("Invalid token type");
            }

            return claims.getSubject();

        } catch (ExpiredJwtException e) {
            throw new SecurityException("Temporary token has expired");
        } catch (JwtException e) {
            throw new SecurityException("Invalid temporary token: " + e.getMessage());
        }
    }
}