package com.tobioxd.keycloak.service.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import com.tobioxd.keycloak.config.JwtAuthConverter;
import com.tobioxd.keycloak.exception.AuthenticationException;
import com.tobioxd.keycloak.exception.UnauthorizedException;
import com.tobioxd.keycloak.payload.dto.LoginDTO;
import com.tobioxd.keycloak.payload.dto.TokenDTO;
import com.tobioxd.keycloak.payload.dto.UserDTO;
import com.tobioxd.keycloak.payload.response.KeyCloakResponse;
import com.tobioxd.keycloak.payload.response.LoginResponse;
import com.tobioxd.keycloak.payload.response.UserListResponse;
import com.tobioxd.keycloak.payload.response.UserResponse;
import com.tobioxd.keycloak.service.base.IKeyCloakUserService;

import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class KeyCloakUserServiceImpl implements IKeyCloakUserService {

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.grant-type}")
    private String grantType;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.token_endpoint}")
    private String tokenEndpoint;

    @Value("${keycloak.end_session_endpoint}")
    private String endSessionEndpoint;

    private final Keycloak keycloak;

    private final RestTemplate restTemplate;

    private final JwtDecoder jwtDecoder;

    private final JwtAuthConverter jwtAuthConverter;

    @Override
    public KeyCloakResponse createUser(UserDTO userDTO) {

        if (!isPasswordValid(userDTO.getPassword())) {
            return KeyCloakResponse.builder().success(false).message(
                    "Password must contain at least 8 characters, 1 uppercase letter, 1 number and 1 special character !")
                    .build();
        }

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

        try {
            Response response = usersResource.create(user);

            if (Objects.equals(201, response.getStatus())) {
                List<UserRepresentation> representationList = usersResource.searchByUsername(userDTO.getUsername(),
                        true);
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
                        .message("User creation failed with status: " + response.getStatus() + " and reason: "
                                + response.getStatusInfo().getReasonPhrase() + ". Error: " + errorMessage)
                        .build();
            }
        } catch (Exception e) {
            e.printStackTrace();
            return KeyCloakResponse.builder().success(false)
                    .message("User creation failed with exception: " + e.getMessage()).build();
        }

    }

    @Override
    public UserResponse getUserDetail(String userId, String token) throws Exception {

        try {

            if (token == null || !token.startsWith("Bearer ")) {
                throw new UnauthorizedException("Invalid token format.");
            }

            String jwtToken = token.substring(7); 

            Jwt jwt = jwtDecoder.decode(jwtToken);

            String tokenUserId = jwtAuthConverter.getPrincipalClaimName(jwt);

            if (!tokenUserId.equals(userId)) {
                throw new AuthenticationException("User not authorized to view this user details !");
            }

            UserRepresentation userRepresentation = getUser(userId);
            return UserResponse.builder()
                    .userId(userRepresentation.getId())
                    .username(userRepresentation.getUsername())
                    .email(userRepresentation.getEmail())
                    .name(userRepresentation.getFirstName() + " " + userRepresentation.getLastName())
                    .build();
        } catch (JwtException e) {
            throw new UnauthorizedException("Invalid token.", e);
        }

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

        } else {
            throw new Exception("User not found !");
        }

    }

    @Override
    public void deleteUser(String userId) {
        getUsersResource().delete(userId);
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
    public UserListResponse getUserList() {

        List<UserRepresentation> userRepresentations = getUsersResource().list();
        List<UserResponse> userDTOList = new ArrayList<>();
        for (UserRepresentation userRepresentation : userRepresentations) {
            UserResponse userResponse = new UserResponse();
            userResponse.setUserId(userRepresentation.getId());
            userResponse.setUsername(userRepresentation.getUsername());
            userResponse.setEmail(userRepresentation.getEmail());
            userResponse.setName(userRepresentation.getFirstName() + " " + userRepresentation.getLastName());
            userDTOList.add(userResponse);
        }
        return UserListResponse.builder().users(userDTOList).build();

    }

    @Override
    public void updatePassword(String userId) {
        UserResource userResource = getUserResource(userId);
        List<String> actions = new ArrayList<>();
        actions.add("UPDATE_PASSWORD");
        userResource.executeActionsEmail(actions);
    }

    @Override
    public ResponseEntity<LoginResponse> login(LoginDTO loginDTO) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", grantType);
        map.add("client_id", clientId);
        map.add("username", loginDTO.getUsername());
        map.add("password", loginDTO.getPassword());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        try {
            ResponseEntity<LoginResponse> response = restTemplate.postForEntity(tokenEndpoint, request,
                    LoginResponse.class);
            return new ResponseEntity<>(response.getBody(), HttpStatus.OK);
        } catch (HttpClientErrorException e) {
            // Log the error and return a response with the appropriate status code
            System.err.println("Error during login: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.valueOf(e.getStatusCode().value()));
        }
    }

    @Override
    public ResponseEntity<KeyCloakResponse> logout(TokenDTO tokenDTO) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("refresh_token", tokenDTO.getToken());

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map, headers);

        ResponseEntity<Response> response = restTemplate.postForEntity(endSessionEndpoint, httpEntity, Response.class);

        KeyCloakResponse res = new KeyCloakResponse();
        if (response.getStatusCode().is2xxSuccessful()) {
            res.setSuccess(true);
            res.setMessage("Logged out successfully");
        }
        return new ResponseEntity<>(res, HttpStatus.OK);
    }

    private boolean isPasswordValid(String password) {
        // Regex to check valid password.
        String regex = "^(?=.*[0-9])(?=.*[A-Z])(?=.*[@#$&*]).{8,}$";
        Pattern p = Pattern.compile(regex);
        if (password == null) {
            return false;
        }
        return p.matcher(password).matches();
    }

    private UsersResource getUsersResource() {
        RealmResource realm1 = keycloak.realm(realm);
        return realm1.users();
    }

    private UserRepresentation getUser(String userId) {
        return getUsersResource().get(userId).toRepresentation();
    }

    private void assignRole(String userId, String roleName) {
        RealmResource realmResource = keycloak.realm(realm);
        RoleRepresentation role = realmResource.roles().get(roleName).toRepresentation();
        realmResource.users().get(userId).roles().realmLevel().add(Collections.singletonList(role));
    }

}
