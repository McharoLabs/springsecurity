package com.seranise.spring.security.springsecurity.repository;

import com.seranise.spring.security.springsecurity.entity.User;
import com.seranise.spring.security.springsecurity.enums.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByEmail(String email);
    Optional<User> findByRoles(Role role);
}
