package com.ronald.springSecurityJWT.dtos;


import java.util.Set;

public record UserDTO(
        String email,
        String username,
        String password,
        Set<String> roles
) {
}
