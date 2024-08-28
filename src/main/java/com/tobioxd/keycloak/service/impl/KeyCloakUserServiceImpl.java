package com.tobioxd.keycloak.service.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import com.tobioxd.keycloak.payload.dto.UserDTO;
import com.tobioxd.keycloak.payload.response.KeyCloakResponse;
import com.tobioxd.keycloak.service.base.IKeyCloakUserService;

import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class KeyCloakUserServiceImpl implements IKeyCloakUserService {

    @Value("${keycloak.realm}")
    private String realm;

    private final Keycloak keycloak;

    @Override
    public KeyCloakResponse createUser(UserDTO userDTO) {

        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
        user.setFirstName(userDTO.getFirstName());
        user.setLastName(userDTO.getLastName());
        user.setEmailVerified(false);

        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setValue(userDTO.getPassword());
        credentialRepresentation.setTemporary(false);
        credentialRepresentation.setType(CredentialRepresentation.PASSWORD);

        List<CredentialRepresentation> list = new ArrayList<>();
        list.add(credentialRepresentation);
        user.setCredentials(list);

        UsersResource usersResource = getUsersResource();

        // Response response = usersResource.create(user);

        try {
            Response response = usersResource.create(user);
        
            if (Objects.equals(201, response.getStatus())) {
                List<UserRepresentation> representationList = usersResource.searchByUsername(userDTO.getUsername(), true);
                if (!CollectionUtils.isEmpty(representationList)) {
                    UserRepresentation userRepresentation1 = representationList.stream()
                        .filter(userRepresentation -> Objects.equals(false, userRepresentation.isEmailVerified()))
                        .findFirst()
                        .orElse(null);
                    assert userRepresentation1 != null;
                    assignRole(userRepresentation1.getId(), "user");
                    emailVerification(userRepresentation1.getId());
                }
                return KeyCloakResponse.builder().success(true).message("User created successfully").build();
            } else {
                String errorMessage = response.readEntity(String.class);
                return KeyCloakResponse.builder().success(false)
                    .message("User creation failed with status: " + response.getStatus() + " and reason: " + response.getStatusInfo().getReasonPhrase() + ". Error: " + errorMessage)
                    .build();
            }
        } catch (Exception e) {
            e.printStackTrace();
            return KeyCloakResponse.builder().success(false).message("User creation failed with exception: " + e.getMessage()).build();
        }

    }

    @Override
    public UserRepresentation getUser(String userId) {
        return getUsersResource().get(userId).toRepresentation();
    }

    @Override
    public void forgotPassword(String userName) throws Exception {
        
        UsersResource usersResource = getUsersResource();
        List<UserRepresentation> representationsList = usersResource.searchByUsername(userName, true);
        
        UserRepresentation userRepresentation = representationsList.stream()
            .findFirst()
            .orElse(null);

        if (userRepresentation != null) {

            updatePassword(userRepresentation.getId());
            return;

        }else{
            throw new Exception("User not found !");
        }

    }

    @Override
    public void deleteUser(String userId) {
        getUsersResource().delete(userId);
    }

    private UsersResource getUsersResource() {
        RealmResource realm1 = keycloak.realm(realm);
        return realm1.users();
    }

    private void assignRole(String userId, String roleName) {
        RealmResource realmResource = keycloak.realm(realm);
        RoleRepresentation role = realmResource.roles().get(roleName).toRepresentation();
        realmResource.users().get(userId).roles().realmLevel().add(Collections.singletonList(role));
    }

    @Override
    public void emailVerification(String userId) {

        UsersResource usersResource = getUsersResource();
        usersResource.get(userId).sendVerifyEmail();
    }

    @Override
    public UserResource getUserResource(String userId) {
        UsersResource usersResource = getUsersResource();
        return usersResource.get(userId);
    }

    @Override
    public void updatePassword(String userId) {
        UserResource userResource = getUserResource(userId);
        List<String> actions = new ArrayList<>();
        actions.add("UPDATE_PASSWORD");
        userResource.executeActionsEmail(actions);
    }

}
