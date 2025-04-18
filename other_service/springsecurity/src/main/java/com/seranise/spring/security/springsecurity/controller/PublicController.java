package com.seranise.spring.security.springsecurity.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("public")
public class PublicController {
    @GetMapping
    public ResponseEntity<Map<String, Object>> helloWorld() {
        return new ResponseEntity<>(Map.of("detail", "Hello world"), HttpStatus.OK);
    }
}
