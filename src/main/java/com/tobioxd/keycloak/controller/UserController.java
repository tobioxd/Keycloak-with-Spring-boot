package com.tobioxd.keycloak.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.tobioxd.keycloak.payload.dto.UserDTO;
import com.tobioxd.keycloak.payload.response.KeyCloakResponse;
import com.tobioxd.keycloak.service.impl.KeyCloakUserServiceImpl;

import lombok.AllArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
@RequestMapping("${api.prefix}")
@AllArgsConstructor
public class UserController {

    private final KeyCloakUserServiceImpl userServiceImpl;

    @PostMapping("/signup")
	public ResponseEntity<KeyCloakResponse> login(@RequestBody UserDTO userDTO) {
		return ResponseEntity.ok(userServiceImpl.createUser(userDTO));
	}

    @PatchMapping("/forgot-password")
    public void forgotPassword(@RequestParam String username) throws Exception {
        userServiceImpl.forgotPassword(username);
    }


}