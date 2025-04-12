package com.seranise.spring.security.springsecurity.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum Role {
    USER("User"),
    ADMIN("Admin"),
    ORGANIZER("Organizer");

    private final String value;
}
