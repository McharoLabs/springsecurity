package com.seranise.spring.security.springsecurity.service;

import com.seranise.spring.security.springsecurity.entity.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashMap;
import java.util.Optional;

public interface JWTService {
    String generateToken(UserDetails userDetails);
    String extractUsername(String token);
    boolean isTokeValid(String token, UserDetails userDetails);

    String generateRefresh(HashMap<Object, Object> extraClaims, UserDetails userDetails);
}
