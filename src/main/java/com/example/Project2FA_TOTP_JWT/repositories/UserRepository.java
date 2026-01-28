package com.example.Project2FA_TOTP_JWT.repositories;

import com.example.Project2FA_TOTP_JWT.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface UserRepository extends JpaRepository<User,Long> {
    Optional<User> findByUsername(String username);
}
