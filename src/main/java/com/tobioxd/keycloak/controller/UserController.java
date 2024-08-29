package com.tobioxd.keycloak.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.tobioxd.keycloak.exception.AuthenticationException;
import com.tobioxd.keycloak.exception.UnauthorizedException;
import com.tobioxd.keycloak.payload.dto.LoginDTO;
import com.tobioxd.keycloak.payload.dto.TokenDTO;
import com.tobioxd.keycloak.payload.dto.UserDTO;
import com.tobioxd.keycloak.payload.response.KeyCloakResponse;
import com.tobioxd.keycloak.payload.response.LoginResponse;
import com.tobioxd.keycloak.payload.response.UserListResponse;
import com.tobioxd.keycloak.service.impl.KeyCloakUserServiceImpl;

import lombok.AllArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.GetMapping;



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

    @GetMapping("/get-all-users")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<UserListResponse> getAllUsers() {
        return ResponseEntity.ok(userServiceImpl.getUserList());
    }

    @GetMapping("/get-user/{userId}")
    public ResponseEntity<?> getUser(@PathVariable String userId, @RequestHeader("Authorization") String token) throws Exception {
        try {
            return ResponseEntity.ok(userServiceImpl.getUserDetail(userId, token));
        } catch (UnauthorizedException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        }
    }

    @PostMapping("/login")
	public ResponseEntity<LoginResponse> login (@RequestBody LoginDTO loginDTO) {
		return userServiceImpl.login(loginDTO);
	}
	
	@PostMapping("/logout")
	public ResponseEntity<KeyCloakResponse> logout (@RequestBody TokenDTO tokenDTO) {
		return userServiceImpl.logout(tokenDTO);
	}

}