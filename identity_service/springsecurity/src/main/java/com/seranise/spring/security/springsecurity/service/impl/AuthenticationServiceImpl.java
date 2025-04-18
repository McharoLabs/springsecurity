package com.seranise.spring.security.springsecurity.service.impl;

import com.seranise.spring.security.springsecurity.dto.CreateUserDTO;
import com.seranise.spring.security.springsecurity.dto.JwtAuthenticationResponseDTO;
import com.seranise.spring.security.springsecurity.dto.RefreshTokenRequest;
import com.seranise.spring.security.springsecurity.dto.SignInRequestDTO;
import com.seranise.spring.security.springsecurity.entity.User;
import com.seranise.spring.security.springsecurity.enums.Role;
import com.seranise.spring.security.springsecurity.exception.BadRequestException;
import com.seranise.spring.security.springsecurity.exception.ConflictException;
import com.seranise.spring.security.springsecurity.exception.NotFoundException;
import com.seranise.spring.security.springsecurity.mapper.AuthenticationMapper;
import com.seranise.spring.security.springsecurity.repository.UserRepository;
import com.seranise.spring.security.springsecurity.service.AuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationServiceImpl.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTServiceImpl jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JWTServiceImpl jwtService, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void signup(CreateUserDTO createUserDTO) throws ConflictException, BadRequestException {
        Optional<User> existingUser = userRepository.findByEmail(createUserDTO.getEmail());
        Map<String, String> errors = new HashMap<>();

        if (existingUser.isPresent()) {
            errors.put("email", "User with this email already exists. Please login or use different email");
            throw new ConflictException(errors);
        }

        User user = AuthenticationMapper.toEntity(createUserDTO);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles(List.of(Role.USER));

        try {
            userRepository.save(user);
        } catch (Exception e) {
            logger.error("An unexpected error occurred.", e);
            throw e;
        }
    }

    @Override
    public JwtAuthenticationResponseDTO signin(SignInRequestDTO signInRequestDTO) throws NotFoundException, BadRequestException {
        Map<String, String> errors = new HashMap<>();

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                signInRequestDTO.getEmail(),
                signInRequestDTO.getPassword()
        ));

        Optional<User> user = userRepository.findByEmail(signInRequestDTO.getEmail());

        if (user.isPresent()) {
            UserDetails userDetails = user.get();
            String access = jwtService.generateToken(userDetails);
            String refresh = jwtService.generateRefresh(new HashMap<>(), userDetails);

            JwtAuthenticationResponseDTO responseDTO = new JwtAuthenticationResponseDTO();
            responseDTO.setAccess(access);
            responseDTO.setRefresh(refresh);

            return responseDTO;
        }

        errors.put("email", "Invalid credentials");
        errors.put("password", "Invalid credentials");
        throw new NotFoundException(errors);
    }

    @Override
    public JwtAuthenticationResponseDTO refreshToken(RefreshTokenRequest refreshTokenRequest) {
        String userEmail = jwtService.extractUsername(refreshTokenRequest.getToken());

        Optional<User> user = userRepository.findByEmail(userEmail);

        if (user.isPresent() && jwtService.isTokeValid(refreshTokenRequest.getToken(), user.get())) {
            String access = jwtService.generateToken(user.get());

            JwtAuthenticationResponseDTO responseDTO = new JwtAuthenticationResponseDTO();
            responseDTO.setAccess(access);
            responseDTO.setRefresh(refreshTokenRequest.getToken());

            return responseDTO;
        }

        return null;
    }
}
