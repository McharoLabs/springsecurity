package com.seranise.spring.security.springsecurity.service.impl;

import com.seranise.spring.security.springsecurity.entity.User;
import com.seranise.spring.security.springsecurity.exception.InvalidTokenException;
import com.seranise.spring.security.springsecurity.service.JWTService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.function.Function;

@Service
public class JWTServiceImpl implements JWTService {
    @Value("${jwt.private.key.path}")
    private Resource privateKeyResource;

    @Value("${jwt.public.key.path}")
    private Resource publicKeyResource;


    private PrivateKey getPrivateKey() {

        try (InputStream inputStream = privateKeyResource.getInputStream()) {
            byte[] keyBytes = inputStream.readAllBytes();
            String privateKeyPEM = new String(keyBytes)
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load private key", e);
        }
    }

    private PublicKey getPublicKey() {
        try (InputStream inputStream = publicKeyResource.getInputStream()) {
            byte[] keyBytes = inputStream.readAllBytes();
            String publicKeyPEM = new String(keyBytes)
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load public key", e);
        }
    }

    @Override
    public String generateToken(UserDetails userDetails) {

        if (userDetails instanceof User user) {
            HashMap<String, Object> claims = getStringObjectHashMap(user);

            return Jwts
                    .builder()
                    .claims(claims)
                    .subject(userDetails.getUsername())
                    .issuedAt(new Date(System.currentTimeMillis()))
                    .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                    .signWith(getPrivateKey(), Jwts.SIG.RS512)
                    .compact();
        }
        return null;

    }

    private static HashMap<String, Object> getStringObjectHashMap(User user) {
        List<String> roleNames = user.getRoles()
                .stream()
                .map(Enum::name)
                .toList();

        HashMap<String, Object> claims = new HashMap<>();

        HashMap<String, Object> userClaims = new HashMap<>();
        userClaims.put("id", user.getId());
        userClaims.put("me", user.getName());

        claims.put("roles", roleNames);
        claims.put("user", userClaims);
        return claims;
    }

    @Override
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public boolean isTokeValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        if (username.equals(userDetails.getUsername()) && !isTokenExpired(token)) {
            return true;
        } else {
            throw new InvalidTokenException("The token is either invalid or expired");
        }
    }

    @Override
    public String generateRefresh(HashMap<Object, Object> extraClaims, UserDetails userDetails) {
        if (userDetails instanceof User user) {
            HashMap<String, Object> claims = getStringObjectHashMap(user);

            return Jwts
                    .builder()
                    .claims(claims)
                    .subject(userDetails.getUsername())
                    .issuedAt(new Date(System.currentTimeMillis()))
                    .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 2))
                    .signWith(getPrivateKey(), Jwts.SIG.RS512)
                    .compact();
        }
        return null;
    }


    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimsResolvers.apply(claims);
    }


    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getPublicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}
