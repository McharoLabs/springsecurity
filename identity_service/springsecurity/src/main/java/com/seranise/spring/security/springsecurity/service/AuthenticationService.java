package com.seranise.spring.security.springsecurity.service;

import com.seranise.spring.security.springsecurity.dto.CreateUserDTO;
import com.seranise.spring.security.springsecurity.dto.JwtAuthenticationResponseDTO;
import com.seranise.spring.security.springsecurity.dto.RefreshTokenRequest;
import com.seranise.spring.security.springsecurity.dto.SignInRequestDTO;
import com.seranise.spring.security.springsecurity.exception.BadRequestException;
import com.seranise.spring.security.springsecurity.exception.ConflictException;
import com.seranise.spring.security.springsecurity.exception.NotFoundException;

public interface AuthenticationService {
    void signup(CreateUserDTO createUserDTO) throws ConflictException, BadRequestException;
    JwtAuthenticationResponseDTO signin(SignInRequestDTO signInRequestDTO) throws NotFoundException, BadRequestException;
    JwtAuthenticationResponseDTO refreshToken (RefreshTokenRequest refreshTokenRequest);
}
