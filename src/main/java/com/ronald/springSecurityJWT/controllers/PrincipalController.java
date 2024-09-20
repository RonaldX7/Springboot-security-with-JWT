package com.ronald.springSecurityJWT.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@PreAuthorize("denyAll()")
public class PrincipalController {

    @GetMapping("/get")
    @PreAuthorize("hasAuthority('READ')")
    public String helloGet() {
        return "Hello World - GET";
    }

    @PostMapping("/post")
    public String helloPost() {
        return "Hello World - POST";
    }

    @PutMapping("/put")
    public String helloPut() {
        return "Hello World - PUT";
    }

    @DeleteMapping("/delete")
    public String helloDelete() {
        return "Hello World - DELETE";
    }

    @PatchMapping("/patch")
    @PreAuthorize("hasAuthority('REFACTOR')")
    public String helloPatch() {
        return "Hello World - PATCH";
    }
}
