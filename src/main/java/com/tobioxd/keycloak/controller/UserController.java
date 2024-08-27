package com.tobioxd.keycloak.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tobioxd.keycloak.payload.dto.LoginDTO;
import com.tobioxd.keycloak.payload.dto.TokenDTO;
import com.tobioxd.keycloak.payload.response.IntrospectResponse;
import com.tobioxd.keycloak.payload.response.LoginResponse;
import com.tobioxd.keycloak.payload.response.Response;
import com.tobioxd.keycloak.service.impl.UserServiceImpl;

import lombok.AllArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
@RequestMapping("${api.prefix}")
@AllArgsConstructor
public class UserController {

    private final UserServiceImpl userServiceImpl;

    @PostMapping("/login")
	public ResponseEntity<LoginResponse> login (@RequestBody LoginDTO loginDTO) {
		return userServiceImpl.login(loginDTO);
	}
	
	@PostMapping("/logout")
	public ResponseEntity<Response> logout (@RequestBody TokenDTO tokenDTO) {
		return userServiceImpl.logout(tokenDTO);
	}
	
	@PostMapping("/introspect")
	public ResponseEntity<IntrospectResponse> introspect(@RequestBody TokenDTO tokenDTO) {
		return userServiceImpl.introspect(tokenDTO);
	}

}
