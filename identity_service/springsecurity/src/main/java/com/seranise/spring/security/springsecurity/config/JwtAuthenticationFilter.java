package com.seranise.spring.security.springsecurity.config;

import com.seranise.spring.security.springsecurity.exception.ForbiddenAccessException;
import com.seranise.spring.security.springsecurity.exception.UnauthorizedAccessException;
import com.seranise.spring.security.springsecurity.service.impl.JWTServiceImpl;
import com.seranise.spring.security.springsecurity.service.impl.UserServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JWTServiceImpl jwtService;
    private final UserServiceImpl userService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Value("${auth.endpoint}")
    private String authEndpoint;


    public JwtAuthenticationFilter(JWTServiceImpl jwtService, UserServiceImpl userService, HandlerExceptionResolver handlerExceptionResolver) {
        this.jwtService = jwtService;
        this.userService = userService;
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            final String authHeader = request.getHeader("Authorization");

            if (request.getServletPath().startsWith(authEndpoint)) {
                filterChain.doFilter(request, response);
                return;
            }

            if (StringUtils.isEmpty(authHeader)) {
                throw new UnauthorizedAccessException("Authorization header is missing. Please provide a valid token.");
            }

            if (!authHeader.startsWith("Bearer ")) {
                throw new ForbiddenAccessException("Invalid Authorization header format. Expected 'Bearer <token>'.");
            }

            final String jwt = authHeader.substring(7);
            final String userEmail = jwtService.extractUsername(jwt);

            if (StringUtils.isNotEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userService.userDetailService().loadUserByUsername(userEmail);

                if (jwtService.isTokeValid(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());

                    token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(token);
                }
            }

            filterChain.doFilter(request, response);

        } catch (Exception ex) {
            handlerExceptionResolver.resolveException(request, response, null, ex);
        }
    }

}
