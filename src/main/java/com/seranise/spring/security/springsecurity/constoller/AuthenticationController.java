package com.seranise.spring.security.springsecurity.constoller;

import com.seranise.spring.security.springsecurity.dto.CreateUserDTO;
import com.seranise.spring.security.springsecurity.dto.JwtAuthenticationResponseDTO;
import com.seranise.spring.security.springsecurity.dto.RefreshTokenRequest;
import com.seranise.spring.security.springsecurity.dto.SignInRequestDTO;
import com.seranise.spring.security.springsecurity.exception.BadRequestException;
import com.seranise.spring.security.springsecurity.exception.ConflictException;
import com.seranise.spring.security.springsecurity.exception.NotFoundException;
import com.seranise.spring.security.springsecurity.service.impl.AuthenticationServiceImpl;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("api/v1/auth")
public class AuthenticationController {
    private final AuthenticationServiceImpl authenticationService;

    public AuthenticationController(AuthenticationServiceImpl authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("signin")
    public ResponseEntity<Map<String, Object>> signin(@Valid @RequestBody SignInRequestDTO signInRequestDTO) {
        Map<String, Object> response = new HashMap<>();

        try {
            JwtAuthenticationResponseDTO responseDTO = authenticationService.signin(signInRequestDTO);

            response.put("token", responseDTO);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (NotFoundException e) {
            response.putAll(e.getErrorMessages());
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            response.put("detail", e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("refresh")
    public ResponseEntity<Map<String, Object>> refresh(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        Map<String, Object> response = new HashMap<>();

        try {
            JwtAuthenticationResponseDTO responseDTO = authenticationService.refreshToken(refreshTokenRequest);

            response.put("token", responseDTO);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (NotFoundException e) {
            response.putAll(e.getErrorMessages());
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            response.put("detail", e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("signup")
    public ResponseEntity<Map<String, Object>> create(@Valid @RequestBody CreateUserDTO userDTO){
        Map<String, Object> response = new HashMap<>();

        try {
            authenticationService.signup(userDTO);
            response.put("detail", "You have successfully registered, you can login");
            return new ResponseEntity<>(response, HttpStatus.CREATED);
        } catch (ConflictException e) {
            response.putAll(e.getErrorMessages());
            return new ResponseEntity<>(response, HttpStatus.CONFLICT);
        } catch (BadRequestException e) {
            response.putAll(e.getErrorMessages());
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            response.put("detail", e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
