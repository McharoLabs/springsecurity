package com.seranise.spring.security.springsecurity.dto;


import com.seranise.spring.security.springsecurity.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDTO {
    private UUID id;

    private String name;
    private String email;
    private List<Role> role;
}
