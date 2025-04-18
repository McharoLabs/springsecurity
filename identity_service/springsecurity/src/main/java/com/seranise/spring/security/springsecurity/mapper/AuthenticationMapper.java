package com.seranise.spring.security.springsecurity.mapper;

import com.seranise.spring.security.springsecurity.dto.CreateUserDTO;
import com.seranise.spring.security.springsecurity.entity.User;

public class AuthenticationMapper {
    public static User toEntity(CreateUserDTO createUserDTO) {
        User user = new User();

        user.setName(createUserDTO.getName());
        user.setEmail(createUserDTO.getEmail());
        user.setPassword(createUserDTO.getPassword());
        user.setRoles(createUserDTO.getRoles());


        return user;
    }
}
