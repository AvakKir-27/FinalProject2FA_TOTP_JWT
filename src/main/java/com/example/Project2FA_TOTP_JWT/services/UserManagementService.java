// UserManagementService.java - с добавлением метода checkPassword
package com.example.Project2FA_TOTP_JWT.services;

import com.example.Project2FA_TOTP_JWT.dto.UserDTO;
import com.example.Project2FA_TOTP_JWT.models.User;
import com.example.Project2FA_TOTP_JWT.repositories.UserRepository;
import com.example.Project2FA_TOTP_JWT.role.Role;
import com.example.Project2FA_TOTP_JWT.security.totp.SecurityTotpAuthCode;
import com.example.Project2FA_TOTP_JWT.security.totp.services.TotpAuthenticationService;
import com.example.Project2FA_TOTP_JWT.security.totp.TotpSetup;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserManagementService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TotpAuthenticationService totpAuthenticationService;
    private final SecurityTotpAuthCode securityTotpAuthCode;

    public List<UserDTO> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }

    @Transactional
    public UserDTO createUser(UserDTO userDto) {
        validateUserDto(userDto);

        if (userRepository.findByUsername(userDto.getUsername()).isPresent()) {
            throw new IllegalArgumentException("User with this username already exists");
        }

        User newUser = new User();
        newUser.setUsername(userDto.getUsername());
        newUser.setPassword(passwordEncoder.encode(userDto.getPassword()));
        newUser.setRole(userDto.getRole() != null ? userDto.getRole() : Role.USER);

        TotpSetup setup = totpAuthenticationService.generate(userDto.getUsername());
        String encryptedSecret = securityTotpAuthCode.encrypt(setup.getSecret());
        newUser.setTotpSecret(encryptedSecret);

        User savedUser = userRepository.save(newUser);
        return convertToDto(savedUser);
    }

    @Transactional
    public UserDTO updateUser(Long userId, UserDTO userDto) {
        User existingUser = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        existingUser.setUsername(userDto.getUsername());

        if (userDto.getPassword() != null && !userDto.getPassword().isEmpty()) {
            existingUser.setPassword(passwordEncoder.encode(userDto.getPassword()));
        }

        User updatedUser = userRepository.save(existingUser);
        return convertToDto(updatedUser);
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> findById(Long userId) {
        return userRepository.findById(userId);
    }

    @Transactional
    public void deleteUser(Long userId) {
        if (!userRepository.existsById(userId)) {
            throw new RuntimeException("User not found with ID: " + userId);
        }
        userRepository.deleteById(userId);
    }

    /**
     * Проверяет соответствие сырого пароля зашифрованному
     *
     * @param rawPassword сырой пароль для проверки
     * @param encodedPassword зашифрованный пароль из базы данных
     * @return true если пароли совпадают
     */
    public boolean checkPassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

    /**
     * Проверяет пароль пользователя по имени пользователя
     *
     * @param username имя пользователя
     * @param rawPassword сырой пароль для проверки
     * @return true если пользователь существует и пароль верный
     */
    public boolean verifyUserPassword(String username, String rawPassword) {
        Optional<User> userOptional = findByUsername(username);
        if (userOptional.isEmpty()) {
            return false;
        }

        User user = userOptional.get();
        return checkPassword(rawPassword, user.getPassword());
    }

    /**
     * Проверяет пароль пользователя по ID
     *
     * @param userId ID пользователя
     * @param rawPassword сырой пароль для проверки
     * @return true если пользователь существует и пароль верный
     */
    public boolean verifyUserPassword(Long userId, String rawPassword) {
        Optional<User> userOptional = findById(userId);
        if (userOptional.isEmpty()) {
            return false;
        }

        User user = userOptional.get();
        return checkPassword(rawPassword, user.getPassword());
    }

    /**
     * Изменяет пароль пользователя
     *
     * @param userId ID пользователя
     * @param oldPassword старый пароль для проверки
     * @param newPassword новый пароль
     * @return true если пароль успешно изменен
     */
    @Transactional
    public boolean changePassword(Long userId, String oldPassword, String newPassword) {
        Optional<User> userOptional = findById(userId);
        if (userOptional.isEmpty()) {
            return false;
        }

        User user = userOptional.get();

        // Проверяем старый пароль
        if (!checkPassword(oldPassword, user.getPassword())) {
            return false;
        }

        // Устанавливаем новый пароль
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        return true;
    }

    private UserDTO convertToDto(User user) {
        UserDTO dto = new UserDTO();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setRole(user.getRole());
        return dto;
    }

    private void validateUserDto(UserDTO dto) {
        if (dto.getUsername() == null || dto.getUsername().trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }

        if (dto.getPassword() == null || dto.getPassword().trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }

        if (dto.getUsername().length() < 3) {
            throw new IllegalArgumentException("Username must be at least 3 characters");
        }
    }
}