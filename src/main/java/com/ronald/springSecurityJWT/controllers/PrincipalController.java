package com.ronald.springSecurityJWT.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@PreAuthorize("denyAll()")
public class PrincipalController {


    @GetMapping("/hello")
    @PreAuthorize("permitAll()")
    public String hello(){
        return "Hello World not secured";
    }

    @GetMapping("/helloSecured")
    @PreAuthorize("hasAuthority('CREATE')")
    public String helloSecured(){
        return "Hello World secured";
    }
}
