package com.seranise.spring.security.springsecurity.mapper;

import com.seranise.spring.security.springsecurity.dto.UserResponseDTO;
import com.seranise.spring.security.springsecurity.dto.CreateUserDTO;
import com.seranise.spring.security.springsecurity.entity.User;

public class UserMapper {
    public static User toEntity(CreateUserDTO createUserDTO) {
        User user = new User();

        user.setName(createUserDTO.getName());
        user.setEmail(createUserDTO.getEmail());
        user.setPassword(createUserDTO.getPassword());
        user.setRoles(createUserDTO.getRoles());


        return user;
    }

    public static UserResponseDTO toResponse(User user) {
        UserResponseDTO responseDTO = new UserResponseDTO();
        responseDTO.setId(user.getId());
        responseDTO.setName(user.getName());
        responseDTO.setEmail(user.getEmail());
        responseDTO.setRole(user.getRoles());

        return responseDTO;
    }
}
