package com.example.Project2FA_TOTP_JWT.security;

import com.example.Project2FA_TOTP_JWT.security.jwt.JwtAuthenticationFilterForSecurity;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilterForSecurity jwtAuthenticationFilterForSecurity;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)

                .authorizeHttpRequests(auth -> auth
                        // 1. Всё публичное — в первую очередь
                        .requestMatchers(
                                "/",
                                "/index.html",
                                "/login.html",
                                "/put_totp.html",
                                "/users.html",
                                "/error",
                                "/auth/**"
                        ).permitAll()

                        // 2. CORS pre-flight
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // 3. Защищённые API
                        .requestMatchers("/api/**").authenticated()

                        // 4. Всё остальное — требует авторизации
                        .anyRequest().authenticated()
                )

                // Добавляем JWT-фильтр
                .addFilterBefore(jwtAuthenticationFilterForSecurity, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}