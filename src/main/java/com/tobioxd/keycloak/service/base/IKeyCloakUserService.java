package com.tobioxd.keycloak.service.base;

import org.keycloak.admin.client.resource.UserResource;
import org.springframework.http.ResponseEntity;

import com.tobioxd.keycloak.payload.dto.LoginDTO;
import com.tobioxd.keycloak.payload.dto.TokenDTO;
import com.tobioxd.keycloak.payload.dto.UserDTO;
import com.tobioxd.keycloak.payload.response.KeyCloakResponse;
import com.tobioxd.keycloak.payload.response.LoginResponse;
import com.tobioxd.keycloak.payload.response.UserListResponse;
import com.tobioxd.keycloak.payload.response.UserResponse;

public interface IKeyCloakUserService {

    KeyCloakResponse createUser(UserDTO userDTO);

    UserResponse getUserDetail(String userId, String token) throws Exception;

    UserListResponse getUserList();

    void emailVerification(String userId);

    void forgotPassword(String userName) throws Exception;

    void deleteUser(String userId);

    UserResource getUserResource(String userId);

    void updatePassword(String userId);

    public ResponseEntity<LoginResponse> login(LoginDTO loginDTO);

    public ResponseEntity<KeyCloakResponse> logout(TokenDTO tokenDTO);
    
} 
