package com.seranise.spring.security.springsecurity.constoller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("api/v1/user")
@PreAuthorize("hasAuthority('ROLE_USER')")
public class UserController {
    @GetMapping
    public ResponseEntity<Map<String, Object>> sayHello() {
        Map<String, Object> response = new HashMap<>();

        response.put("message", "If you see this, authorization with role based is working");
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
