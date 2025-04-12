package com.seranise.spring.security.springsecurity.seed;

import com.seranise.spring.security.springsecurity.entity.User;
import com.seranise.spring.security.springsecurity.enums.Role;
import com.seranise.spring.security.springsecurity.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

@Configuration
public class AdminSeeder {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AdminSeeder(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public CommandLineRunner seedAdminUser() {
        return args -> {
            Optional<User> adminExists = userRepository.findByRole(Role.ADMIN);

            if (adminExists.isEmpty()) {
                User admin = new User();

                admin.setName("Godfrey Mcharo");
                admin.setEmail("mcharoprofg23@gmail.com");
                admin.setRole(Role.ADMIN);
                admin.setPassword(passwordEncoder.encode("admin"));

                userRepository.save(admin);
                System.out.println("✅ Admin user created.");
            } else {
                System.out.println("ℹ️ Admin user already exists.");
            }

        };
    }
}
