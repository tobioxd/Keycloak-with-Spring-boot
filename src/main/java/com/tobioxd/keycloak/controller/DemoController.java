package com.tobioxd.keycloak.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;


@RestController
@RequestMapping("${api.prefix}")
public class DemoController {

    @GetMapping("/hello")
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('client_admin')")
    public ResponseEntity<String> sayHelloToAdmin() {
        return ResponseEntity.ok("Hello from Spring Boot and Keycloak - ADMIN ");
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('client_user')")
    public ResponseEntity<String> sayHelloToUser() {
        return ResponseEntity.ok("Hello from Spring Boot and Keycloak - USER ");
    }

}
