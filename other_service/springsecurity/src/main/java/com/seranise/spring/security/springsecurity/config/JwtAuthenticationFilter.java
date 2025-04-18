package com.seranise.spring.security.springsecurity.config;

import com.seranise.spring.security.springsecurity.utils.JWTValidator;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JWTValidator jwtValidator;

    public JwtAuthenticationFilter(PublicKey publicKey) {
        this.jwtValidator = new JWTValidator(publicKey);
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest httpRequest,
            @NonNull HttpServletResponse httpResponse,
            @NonNull FilterChain chain
    )
            throws ServletException, IOException {

        String requestUri = httpRequest.getRequestURI();

        // Skip JWT filter for public endpoints
        if (requestUri.equals("/public") || requestUri.startsWith("/public/") || requestUri.startsWith("/error")) {
            chain.doFilter(httpRequest, httpResponse);
            return;
        }

        final String authHeader = httpRequest.getHeader("Authorization");

        if (StringUtils.isBlank(authHeader) || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(httpRequest, httpResponse);
            return;
        }

        final String token = authHeader.substring(7);

        try {
            if (jwtValidator.isTokenValid(token)) {
                Claims claims = jwtValidator.extractAllClaims(token);
                String username = claims.getSubject();

                String userId = claims.get("user", Map.class) != null ? (String) ((Map) claims.get("user")).get("id") : null;

                @SuppressWarnings("unchecked")
                List<String> roles = claims.get("roles", List.class);
                Collection<GrantedAuthority> authorities = roles != null
                        ? roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList())
                        : Collections.emptyList();
                System.out.println(authorities);

                var authToken = new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        authorities
                );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
                SecurityContextHolder.getContext().setAuthentication(authToken);

                httpRequest.setAttribute("userId", userId);
            }
        } catch (Exception ex) {
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
            return;
        }

        chain.doFilter(httpRequest, httpResponse);
    }
}
