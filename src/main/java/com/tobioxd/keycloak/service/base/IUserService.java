package com.tobioxd.keycloak.service.base;

import org.springframework.http.ResponseEntity;

import com.tobioxd.keycloak.payload.dto.LoginDTO;
import com.tobioxd.keycloak.payload.dto.TokenDTO;
import com.tobioxd.keycloak.payload.response.IntrospectResponse;
import com.tobioxd.keycloak.payload.response.LoginResponse;
import com.tobioxd.keycloak.payload.response.Response;

public interface IUserService {

    public ResponseEntity<LoginResponse> login(LoginDTO loginDTO);

    public ResponseEntity<Response> logout(TokenDTO tokenDTO);

    public ResponseEntity<IntrospectResponse> introspect(String token);

}
