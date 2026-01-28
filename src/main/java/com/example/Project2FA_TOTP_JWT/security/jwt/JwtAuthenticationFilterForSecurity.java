package com.example.Project2FA_TOTP_JWT.security.jwt;

import com.example.Project2FA_TOTP_JWT.models.User;
import com.example.Project2FA_TOTP_JWT.repositories.UserRepository;
import com.example.Project2FA_TOTP_JWT.security.jwt.service.JwtTokenService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Component
public class JwtAuthenticationFilterForSecurity extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;
    private final UserRepository userRepository;

    public JwtAuthenticationFilterForSecurity(JwtTokenService jwtTokenService, UserRepository userRepository) {
        this.jwtTokenService = jwtTokenService;
        this.userRepository=userRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        // Пропускаем без проверки токена ВСЕ публичные пути
        return path.startsWith("/auth/") ||
                path.equals("/login.html") ||
                path.equals("/put_totp.html") ||
                path.equals("/index.html") ||
                path.equals("/") ||
                path.equals("/error") ||
                path.startsWith("/static/");  // если статика в отдельной папке
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {

        String path = request.getRequestURI();
        System.out.println("=== JwtFilter обработка пути: " + path + " ===");

        String header = request.getHeader("Authorization");

        // Если нет заголовка — для защищённых путей отклоняем
        if (header == null || !header.startsWith("Bearer ")) {
            System.out.println("Нет заголовка Authorization или не Bearer");

            // Только для API-админки требуем токен строго
            if (path.startsWith("/api/admin")) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Требуется авторизация");
                return;
            }

            // Для остальных защищённых путей — просто пропускаем без аутентификации
            // (Spring Security сам решит по .authenticated())
            chain.doFilter(request, response);
            return;
        }

        String token = header.substring(7);
        System.out.println("Получен токен: " + token.substring(0, 20) + "...");

        if (!jwtTokenService.isValid(token)) {
            System.out.println("Токен невалиден");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Невалидный токен");
            return;
        }

        try {
            Claims claims = jwtTokenService.getClaims(token);
            String username = claims.getSubject();
            String role = claims.get("role", String.class);

            Optional<User> userOpt = userRepository.findByUsername(username);
            if (userOpt.isEmpty()) {
                System.out.println("Пользователь с username " + username + " не найден в БД — токен инвалидируем");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Пользователь не найден");
                return;
            }
            User user = userOpt.get();
            if (!user.isTotpEnabled()) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "2FA не включено");
                return;
            }

            System.out.println("Пользователь: " + username + ", Роль: " + role);

            // Устанавливаем аутентификацию
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_" + role))
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        } catch (Exception e) {
            System.out.println("Ошибка в JwtFilter: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Ошибка авторизации");
        }
    }
}