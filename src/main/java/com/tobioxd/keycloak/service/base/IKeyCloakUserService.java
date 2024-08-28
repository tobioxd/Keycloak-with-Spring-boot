package com.tobioxd.keycloak.service.base;

import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.UserRepresentation;

import com.tobioxd.keycloak.payload.dto.UserDTO;
import com.tobioxd.keycloak.payload.response.KeyCloakResponse;

public interface IKeyCloakUserService {

    KeyCloakResponse createUser(UserDTO userDTO);

    UserRepresentation getUser(String userId);

    void emailVerification(String userId);

    void forgotPassword(String userName) throws Exception;

    void deleteUser(String userId);

    UserResource getUserResource(String userId);

    void updatePassword(String userId);
    
} 
