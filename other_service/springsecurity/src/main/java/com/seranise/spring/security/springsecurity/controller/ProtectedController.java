package com.seranise.spring.security.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("protected")
public class ProtectedController {
    @GetMapping
    public String protectedMethod() {return "Protected";}

    @GetMapping("admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String admin(@RequestAttribute("userId") String userId) {return "I am admin. User ID: " + userId;}
}
