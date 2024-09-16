package com.ronald.springSecurityJWT.controllers;

import com.ronald.springSecurityJWT.dtos.UserDTO;
import com.ronald.springSecurityJWT.entities.ERole;
import com.ronald.springSecurityJWT.entities.RoleEntity;
import com.ronald.springSecurityJWT.entities.UserEntity;
import com.ronald.springSecurityJWT.repositories.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@PreAuthorize("denyAll()")
public class PrincipalController {


    @GetMapping("/hello")
    public String hello(){
        return "Hello World not secured";
    }

    @GetMapping("/helloSecured")
    public String helloSecured(){
        return "Hello World secured";
    }
}
