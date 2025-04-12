package com.seranise.spring.security.springsecurity.config;

import com.seranise.spring.security.springsecurity.exception.ForbiddenAccessException;
import com.seranise.spring.security.springsecurity.exception.InvalidTokenException;
import com.seranise.spring.security.springsecurity.exception.UnauthorizedAccessException;
import com.seranise.spring.security.springsecurity.service.impl.JWTServiceImpl;
import com.seranise.spring.security.springsecurity.service.impl.UserServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JWTServiceImpl jwtService;
    private final UserServiceImpl userService;

    public JwtAuthenticationFilter(JWTServiceImpl jwtService, UserServiceImpl userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // If the Authorization header is missing, return 401 Unauthorized
        if (StringUtils.isEmpty(authHeader)) {
            throw new UnauthorizedAccessException("Authorization header is missing. Please provide a valid token.");
        }

        // If the Authorization header doesn't start with "Bearer ", return 403 Forbidden
        if (!StringUtils.startsWith(authHeader, "Bearer ")) {
            throw new ForbiddenAccessException("Invalid Authorization header format. Expected 'Bearer <token>'.");
        }

        // Extract the token from the header
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);

        // If a valid user email exists and the security context is empty, try to authenticate the user
        if (StringUtils.isNotEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userService.userDetailService().loadUserByUsername(userEmail);

            try {
                // Check if the token is valid
                if (jwtService.isTokeValid(jwt, userDetails)) {
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );

                    token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(token);

                    SecurityContextHolder.setContext(securityContext);
                }
            } catch (InvalidTokenException e) {
                throw new ForbiddenAccessException("Invalid or expired token.");
            }
        }

        // Continue the filter chain
        filterChain.doFilter(request, response);
    }

}
